import socket

# Test that the TCP connection is open
def tcp_client():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('YOUR_ADDRESS', YOUR_PORT))

        message = "start ACQ"  # Replace it with your tcp command
        client_socket.sendall(message.encode('utf-8'))

        data = client_socket.recv(1024)
        print("Server response:", data.decode('utf-8'))

    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    tcp_client()
