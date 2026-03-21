# Robotics Security Simulation (ROS)

Lightweight ROS module that reacts to backend security alerts.

## Structure

- `ros_nodes/alert_subscriber.py` - subscribes to `/security_alerts`, logs alerts, triggers robot behavior
- `ros_nodes/robot_controller.py` - simple state-based robot reaction logic
- `integration/bridge.py` - publisher bridge function `send_alert_to_ros(alert_data)`
- `gazebo_world/minimal.world` - minimal Gazebo world (ground + sun only)
- `send_test_alert.py` - CLI helper to publish test alerts

## Alert Message Format

```json
{
  "type": "phishing_ui | vulnerability | attack_detected",
  "severity": "High | Medium | Low",
  "source": "scanner | ai | attack",
  "timestamp": "ISO-8601",
  "message": "text"
}
```

## Execution Flow

1. Start ROS core:
   - `roscore`
2. Run subscriber node (new terminal):
   - `cd robotics/ros_nodes`
   - `python alert_subscriber.py`
3. Send test alert (new terminal):
   - `cd robotics`
   - `python send_test_alert.py --type vulnerability --severity High --source scanner --message "High-risk finding"`
4. Observe subscriber logs and robot state response in console.

## Optional Gazebo Startup

- `gazebo robotics/gazebo_world/minimal.world`

This world is intentionally lightweight and local-only.
