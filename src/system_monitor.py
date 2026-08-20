import psutil


def get_system_metrics():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "cpu_percent": cpu,
        "memory_percent": memory.percent,
        "disk_percent": disk.percent
    }


if __name__ == "__main__":
    metrics = get_system_metrics()

    print("=== CloudSentinel System Monitor ===")

    # CPU monitoring
    print(f"CPU Usage: {metrics['cpu_percent']}%")

    if metrics["cpu_percent"] > 80:
        print("🚨 ALERT: High CPU usage detected!")

    # Memory monitoring
    print(f"Memory Usage: {metrics['memory_percent']}%")

    if metrics["memory_percent"] > 80:
        print("🚨 ALERT: High memory usage detected!")

    # Disk monitoring
    print(f"Disk Usage: {metrics['disk_percent']}%")
