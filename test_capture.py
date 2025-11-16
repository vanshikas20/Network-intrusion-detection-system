import pyshark

print("Testing packet capture...")

try:
    # Test with your interface
    capture = pyshark.LiveCapture(interface='Wi-Fi')
    
    print("✅ Capture initialized successfully!")
    print("Capturing 5 packets...")
    
    for i, packet in enumerate(capture.sniff_continuously()):
        print(f"Packet {i+1}: {packet}")
        if i >= 4:
            break
    
    print("✅ SUCCESS! Packet capture is working!")
    
except Exception as e:
    print(f"❌ ERROR: {e}")
    print("\nPossible fixes:")
    print("1. Run as Administrator")
    print("2. Install Npcap from https://npcap.com/")
    print("3. Restart computer after installing Npcap")