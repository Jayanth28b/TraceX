import json
import random


def generate_dataset(output_path="samples/ai_training_data.json"):
    random.seed(42)

    evidence = []

    # Normal traffic
    for i in range(100):
        evidence.append({
            "timestamp": 1000000 + i,
            "source_ip": "192.168.1.10",
            "destination_ip": random.choice([
                "192.168.1.20",
                "192.168.1.30",
                "8.8.8.8",
            ]),
            "protocol": random.choice(["TCP", "UDP"]),
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([53, 80, 443]),
            "dns_query": (
                "example.com"
                if random.random() < 0.3
                else None
            ),
            "packet_length": random.randint(50, 1500),
        })

    # Synthetic anomalous traffic
    for i in range(10):
        evidence.append({
            "timestamp": 2000000 + i,
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.50",
            "protocol": "TCP",
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([
                21, 23, 445, 3389, 4444
            ]),
            "dns_query": None,
            "packet_length": random.randint(1, 100),
        })

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=4)

    print(f"Generated {len(evidence)} synthetic events.")
    print(f"Dataset saved to: {output_path}")


if __name__ == "__main__":
    generate_dataset()