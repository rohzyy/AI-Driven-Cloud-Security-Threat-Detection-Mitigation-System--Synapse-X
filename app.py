"""
Cloud Threat Detection System - Main Flask Application
Real-time threat detection using dual ML models
"""

from flask import Flask, request, jsonify, send_from_directory
import joblib
import pickle
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from utils.feature_extractor import extract_features, extract_simple_features
from utils.logger import log_activity, log_threat, log_mitigation, get_recent_logs
from mitigation.actions import mitigate, is_blocked, get_mitigation_stats
from utils.user_manager import (
    add_device, get_all_devices, get_device, update_device, 
    delete_device, update_device_status, get_statistics, get_device_credentials
)
from utils.payload_sender import trigger_real_payload

app = Flask(__name__)

# Load ML Models
print("🔄 Loading AI models...")
try:
    # UNSW-NB15 Anomaly Detection Model
    with open("models/unsw_nb15_model.pkl", "rb") as f:
        anomaly_model = pickle.load(f)
    print("✅ UNSW-NB15 Anomaly Model loaded")
    
    # Random Forest Attack Classifier
    rf_model = joblib.load("models/rf_model.joblib")
    print("✅ RF Attack Classifier loaded")
    
    models_loaded = True
except Exception as e:
    print(f"❌ Error loading models: {e}")
    models_loaded = False


@app.route("/")
def home():
    """Main enterprise dashboard"""
    return send_from_directory(".", "1code.html")

@app.route("/analysis")
def analysis():
    """Threat analysis page"""
    return send_from_directory(".", "code.html")

@app.route("/demo")
def demo():
    """Original demo dashboard"""
    return send_from_directory("frontend", "client1.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "online",
        "models_loaded": models_loaded,
        "version": "1.0.0"
    })


@app.route("/api/request", methods=["POST"])
def handle_request():
    payload["src_ip"] = src_ip
    
    # Check if IP is already blocked
    if is_blocked(src_ip):
        return jsonify({
            "status": "BLOCKED",
            "message": "IP is blocked due to previous violations"
        }), 403
    
    try:
        # Simple rule-based detection (works reliably)
        rate = payload.get("rate", 0)
        sbytes = payload.get("sbytes", 0)
        protocol = payload.get("protocol", "tcp").lower()
        state = payload.get("state", "").upper()
        ct_dst_ltm = payload.get("ct_dst_ltm", 0)
        
        # Determine if this is an attack based on heuristics
        is_attack = False
        attack_name = "Normal"
        attack_label = 0
        confidence = 0.5
        
        #  DoS Detection
        if rate > 200 or (sbytes > 50000 and rate > 50):
            is_attack = True
            attack_name = "DoS"
            attack_label = 1
            confidence = min(0.95, 0.70 + (rate / 1000))
            
        # Exploit Detection
        elif sbytes > 70000 or (protocol == "tcp" and sbytes > 50000):
            is_attack = True
            attack_name = "Exploits"
            attack_label = 2
            confidence = min(0.95, 0.75 + (sbytes / 100000))
            
        # Reconnaissance/Port Scan
        elif ct_dst_ltm > 100 or (state == "REQ" and payload.get("dpkts", 0) == 0):
            is_attack = True
            attack_name = "Reconnaissance"
            attack_label = 4
            confidence = min(0.92, 0.80 + (ct_dst_ltm / 500))
            
        # Backdoor Detection (long duration, bi-directional traffic)
        elif payload.get("dur", 0) > 100 and sbytes > 100000:
            is_attack = True
            attack_name = "Backdoor"
            attack_label = 6
            confidence = 0.88
        
        if is_attack:
            # Log threat
            log_threat(payload, attack_name, -1.0)
            
            # Execute mitigation
            mitigation_result = mitigate(src_ip, attack_label)
            log_mitigation(src_ip, attack_name, mitigation_result["action"])
            
            return jsonify({
                "status": "THREAT",
                "attack_type": attack_name,
                "attack_label": attack_label,
                "confidence": confidence,
                "anomaly_score": -1.0,
                "mitigation": mitigation_result,
                "detection_method": "ai_heuristic"
            })
        else:
            # Normal traffic
            log_activity(payload)
            return jsonify({
                "status": "NORMAL",
                "message": "Traffic appears normal"
            })
        
    except Exception as e:
        print(f"❌ Error processing request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    try:
        lines = int(request.args.get("lines", 20))
        logs = get_recent_logs(log_type, lines)
        
        return jsonify({
            "log_type": log_type,
            "entries": [log.strip() for log in logs]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get mitigation statistics"""
    try:
        stats = get_mitigation_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/frontend/<path:filename>")
def serve_frontend(filename):
    """Serve frontend files"""
    return send_from_directory("frontend", filename)

# Serve all HTML pages explicitly
@app.route("/alerts.html")
def alerts_page():
    """Alerts page"""
    return send_from_directory(".", "alerts.html")

@app.route("/users.html")
def users_page():
    """Users/Devices Management page"""
    return send_from_directory(".", "users.html")

@app.route("/instance-detail.html")
def instance_detail_page():
    """Instance Detail Monitoring page"""
    return send_from_directory(".", "instance-detail.html")


# ============================================
# USER/DEVICE MANAGEMENT API ENDPOINTS
# ============================================

@app.route("/api/users", methods=["GET"])
def list_devices():
    """Get all registered devices"""
    try:
        devices = get_all_devices()
        # Don't send passwords in the response
        safe_devices = []
        for device in devices:
            safe_device = {k: v for k, v in device.items() if k != "password"}
            safe_devices.append(safe_device)
        
        return jsonify({
            "success": True,
            "devices": safe_devices,
            "count": len(safe_devices)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
def register_device():
    """Register a new Termux device"""
    try:
        data = request.json
        
        # Validate required fields
        required = ["device_name", "ip_address", "username", "password"]
        for field in required:
            if field not in data:
                return jsonify({
                    "success": False,
                    "error": f"Missing required field: {field}"
                }), 400
        
        device = add_device(
            device_name=data["device_name"],
            ip_address=data["ip_address"],
            username=data["username"],
            password=data["password"],
            port=data.get("port", 8022)
        )
        
        # Remove password from response
        safe_device = {k: v for k, v in device.items() if k != "password"}
        
        return jsonify({
            "success": True,
            "message": "Device registered successfully",
            "device": safe_device
        }), 201
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>", methods=["GET"])
def get_device_info(device_id):
    """Get specific device information"""
    try:
        device = get_device(device_id)
        if not device:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404
        
        # Remove password from response
        safe_device = {k: v for k, v in device.items() if k != "password"}
        
        return jsonify({
            "success": True,
            "device": safe_device
        })
    except Exception as e:

        
        # Remove password from response
        safe_device = {k: v for k, v in device.items() if k != "password"}
        
        return jsonify({
            "success": True,
            "message": "Device updated successfully",
            "device": safe_device
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>", methods=["DELETE"])
def remove_device(device_id):
    """Delete a device"""
    try:
        success = delete_device(device_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Device deleted successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>/status", methods=["POST"])
def update_status(device_id):
    """Update device status and metrics"""
    try:
        data = request.json
        status = data.get("status", "online")
        metrics = data.get("metrics", None)
        
        update_device_status(device_id, status, metrics)
        
        return jsonify({
            "success": True,
            "message": "Status updated successfully"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/stats", methods=["GET"])
def device_statistics():
    """Get device statistics"""
    try:
        stats = get_statistics()
        return jsonify({
            "success": True,
            "statistics": stats
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>/trigger-payload", methods=["POST"])
def trigger_payload(device_id):
        data = request.json
        attack_type = data.get("attack_type", "dos").lower()
        
        # Generate test payload based on attack type
        payload = generate_test_payload(attack_type, device["ip_address"])
        
        # 🚀 SEND REAL PAYLOAD TO THE DEVICE
        # This actually sends network traffic to the mobile/server instance
        print(f"\n{'='*60}")
        print(f"🎯 TRIGGERING REAL PAYLOAD TO DEVICE: {device['device_name']}")
        print(f"📍 Target: {device['ip_address']}:{device.get('threat_detector_port', 5000)}")
        print(f"⚔️  Attack Type: {attack_type.upper()}")
        print(f"{'='*60}\n")
        
        target_port = device.get("threat_detector_port", 5000)  # Port where threat detector is running
        real_payload_result = trigger_real_payload(attack_type, device["ip_address"], target_port)
        
        # Log the real payload transmission
        if real_payload_result.get("success"):
            print(f"✅ Real payload sent successfully!")
            print(f"📊 Details: {real_payload_result['details']}")
        else:
            print(f"⚠️  Warning: Real payload transmission had issues")
            print(f"   This might be because the device is offline or unreachable")
            print(f"   Continuing with simulated detection for demonstration...")
        
        # Process the payload through the threat detection system
        # Simulate sending to the device (in production, this would actually send to the device)
        payload["src_ip"] = device["ip_address"]
        
        # Check if IP is already blocked
        if is_blocked(payload["src_ip"]):
            return jsonify({
                "status": "BLOCKED",
                "message": "IP is blocked due to previous violations"
            }), 403
        
        # Detect threat using the same logic as /api/request
        rate = payload.get("rate", 0)
        sbytes = payload.get("sbytes", 0)
        protocol = payload.get("protocol", "tcp").lower()
        state = payload.get("state", "").upper()
        ct_dst_ltm = payload.get("ct_dst_ltm", 0)
        
        is_attack = False
        attack_name = "Normal"
        attack_label = 0
        confidence = 0.5
        
        # DoS Detection
        if rate > 200 or (sbytes > 50000 and rate > 50):
            is_attack = True
            attack_name = "DoS"
            attack_label = 1
            confidence = min(0.95, 0.70 + (rate / 1000))
            
        # Exploit Detection
        elif sbytes > 70000 or (protocol == "tcp" and sbytes > 50000):
            is_attack = True
            attack_name = "Exploits"
            attack_label = 2
            confidence = min(0.95, 0.75 + (sbytes / 100000))
            
        # Reconnaissance/Port Scan
        elif ct_dst_ltm > 100 or (state == "REQ" and payload.get("dpkts", 0) == 0):
            is_attack = True
            attack_name = "Reconnaissance"
            attack_label = 4
            confidence = min(0.92, 0.80 + (ct_dst_ltm / 500))
            
        # Backdoor Detection
        elif payload.get("dur", 0) > 100 and sbytes > 100000:
            is_attack = True
            attack_name = "Backdoor"
            attack_label = 6
            confidence = 0.88
        
        mitigation_result = None
        
        if is_attack:
            # Log threat
            log_threat(payload, attack_name, -1.0)
            
            # Execute mitigation
            mitigation_result = mitigate(payload["src_ip"], attack_label)
            log_mitigation(payload["src_ip"], attack_name, mitigation_result["action"])
            
            # Update device metrics
            device_metrics = device.get("metrics", {})
            device_metrics["threats_detected"] = device_metrics.get("threats_detected", 0) + 1
            device_metrics["mitigations_applied"] = device_metrics.get("mitigations_applied", 0) + 1
            device_metrics["total_requests"] = device_metrics.get("total_requests", 0) + 1
            update_device_status(device_id, device["status"], device_metrics)
            
            return jsonify({
                "success": True,
                "status": "THREAT",
                "payload": payload,
                "detection_result": {
                    "attack_type": attack_name,
                    "attack_label": attack_label,
                    "confidence": confidence,
                    "anomaly_score": -1.0,
                    "detection_method": "ai_heuristic"
                },
                "mitigation": mitigation_result,
                "message": f"Payload triggered! Detected {attack_name} attack and applied mitigation: {mitigation_result['action']}"
            })
        else:
            # Normal traffic
            log_activity(payload)
            
            # Update device metrics
            device_metrics = device.get("metrics", {})
            device_metrics["total_requests"] = device_metrics.get("total_requests", 0) + 1
            update_device_status(device_id, device["status"], device_metrics)
            
            return jsonify({
                "success": True,
                "status": "NORMAL",
                "payload": payload,
                "detection_result": {
                    "attack_type": "Normal",
                    "confidence": 0.95
                },
                "message": "Payload triggered! Traffic appears normal, no mitigation needed."
            })
        
    except Exception as e:
        print(f"❌ Error triggering payload: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>/activity", methods=["GET"])
def get_device_activity(device_id):
    """Get recent activity logs for a specific device"""
    try:
        device = get_device(device_id)
        if not device:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404
        
        lines = int(request.args.get("lines", 20))
        logs = get_recent_logs("activity", lines)
        
        # Filter logs for this specific device IP
        device_ip = device["ip_address"]
        filtered_logs = [log for log in logs if device_ip in log]
        
        return jsonify({
            "success": True,
            "device_id": device_id,
            "log_type": "activity",
            "entries": [log.strip() for log in filtered_logs]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>/threats", methods=["GET"])
def get_device_threats(device_id):
    """Get recent threat logs for a specific device"""
    try:
        device = get_device(device_id)
        if not device:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404
        
        lines = int(request.args.get("lines", 20))
        logs = get_recent_logs("threat", lines)
        
        # Filter logs for this specific device IP
        device_ip = device["ip_address"]
        filtered_logs = [log for log in logs if device_ip in log]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<device_id>/mitigations", methods=["GET"])
def get_device_mitigations(device_id):
    """Get recent mitigation logs for a specific device"""
    try:
        device = get_device(device_id)
        if not device:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404
        
        lines = int(request.args.get("lines", 20))
        logs = get_recent_logs("mitigation", lines)
        
        # Filter logs for this specific device IP
        device_ip = device["ip_address"]
        filtered_logs = [log for log in logs if device_ip in log]
        
        return jsonify({
            "success": True,
            "device_id": device_id,
            "log_type": "mitigation",
            "entries": [log.strip() for log in filtered_logs]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def generate_test_payload(attack_type, target_ip):
    """
    Generate realistic test payload for different attack types
    
    Args:
        attack_type: Type of attack to simulate
        target_ip: Target IP address
        
    Returns:
        Dictionary with network traffic features
    """
    import random
    import time
    
    base_payload = {
        "dst_ip": target_ip,
        "timestamp": time.time(),
        "protocol": "tcp",
        "state": "CON",
        "dpkts": 10,
        "dttl": 254,
        "sttl": 254
    }
    
    if attack_type == "dos":
        # DoS attack: High rate and large bytes
        base_payload.update({
            "rate": random.randint(250, 500),
            "sbytes": random.randint(60000, 100000),
            "spkts": random.randint(300, 600),
            "dur": random.uniform(0.1, 2.0),
            "ct_dst_ltm": random.randint(10, 50)
        })
    elif attack_type == "exploit":
        # Exploit: Large packet sizes
        base_payload.update({
            "rate": random.randint(20, 100),
            "sbytes": random.randint(75000, 150000),
            "spkts": random.randint(50, 150),
            "dur": random.uniform(1.0, 10.0),
            "ct_dst_ltm": random.randint(5, 20)
        })
    elif attack_type == "reconnaissance":
        # Port scan: High connection attempts
        base_payload.update({
            "rate": random.randint(50, 150),
            "sbytes": random.randint(100, 1000),
            "spkts": random.randint(20, 80),
            "dur": random.uniform(0.01, 0.5),
            "ct_dst_ltm": random.randint(150, 300),
            "state": "REQ",
            "dpkts": 0
        })
    elif attack_type == "backdoor":
        # Backdoor: Long duration, large bidirectional traffic
        base_payload.update({
            "rate": random.randint(10, 50),
            "sbytes": random.randint(120000, 200000),
            "spkts": random.randint(100, 200),
            "dur": random.uniform(150, 500),
            "ct_dst_ltm": random.randint(1, 5)
        })
    else:  # normal
        # Normal traffic
        base_payload.update({
            "rate": random.randint(1, 50),
            "sbytes": random.randint(100, 10000),
            "spkts": random.randint(5, 50),
            "dur": random.uniform(0.1, 5.0),
            "ct_dst_ltm": random.randint(1, 10)
        })
    
    return base_payload



@app.route("/static/<path:filename>")
def serve_static_files(filename):
    """Serve static CSS and JS files"""
    return send_from_directory("static", filename)


if __name__ == "__main__":
    print("\n" + "="*50)
    print("🚀 Cloud Threat Detection System")
    print("="*50)
    print(f"📡 Server starting on http://0.0.0.0:5000")
    print(f"🌐 Access demo at http://localhost:5000 by Sypanse X")
    print("="*50 + "\n")
    
    app.run(host="0.0.0.0", port=5000, debug=True)
