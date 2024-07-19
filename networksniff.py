from scapy.all import sniff, IP, TCP, UDP
from scapy.layers import http
from prettytable import PrettyTable
import datetime
from user_agents import parse

banner = """

███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗    ███████╗███╗   ██╗██╗███████╗███████╗██╗███╗   ██╗ ██████╗     ████████╗ ██████╗  ██████╗ ██╗     
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██║████╗  ██║██╔════╝     ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝     ███████╗██╔██╗ ██║██║█████╗  █████╗  ██║██╔██╗ ██║██║  ███╗       ██║   ██║   ██║██║   ██║██║     
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗     ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██║██║╚██╗██║██║   ██║       ██║   ██║   ██║██║   ██║██║     
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗    ███████║██║ ╚████║██║██║     ██║     ██║██║ ╚████║╚██████╔╝       ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
╔╦╗┌─┐┌┬┐┌─┐  ╔╗ ┬ ┬  ╔╦╗┌─┐┬  ┬  ╔═╗┬ ┬┌┬┐┬ ┬┌─┐┬─┐
║║║├─┤ ││├┤   ╠╩╗└┬┘   ║║├┤ └┐┌┘  ╚═╗│ │ │ ├─┤├─┤├┬┘
╩ ╩┴ ┴─┴┘└─┘  ╚═╝ ┴   ═╩╝└─┘ └┘   ╚═╝└─┘ ┴ ┴ ┴┴ ┴┴└─                                                                                                                 
                                                                                                                                                                    
"""

print(banner)


# ANSI color codes
COLOR_GREEN = '\033[92m'  # Green color
COLOR_RED = '\033[91m'    # Red color
COLOR_END = '\033[0m'     # Reset color to default

def extract_browser_info(user_agent):
    ua = parse(user_agent)
    browser = ua.browser.family if ua.browser.family else 'Unknown'
    os = ua.os.family if ua.os.family else 'Unknown'
    device = ua.device.family if ua.device.family else 'Unknown'
    return f"{browser} on {os} ({device})"

def extract_form_data(packet):
    fields = {}
    if packet.haslayer(http.HTTPRequest):
        http_request = packet.getlayer(http.HTTPRequest)
        if http_request.Method == b'POST':
            load = packet.load.decode()
            for field in load.split('&'):
                field_name, field_value = field.split('=')
                fields[field_name] = field_value
    return fields

def packet_callback(packet):
    if IP in packet:
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            src_port = 'N/A'
            dst_port = 'N/A'

        if packet.haslayer(http.HTTPRequest):
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            host = packet[http.HTTPRequest].Host.decode()
            method = packet[http.HTTPRequest].Method.decode()
            path = packet[http.HTTPRequest].Path.decode()

            if http.HTTPRequest in packet:
                user_agent = packet[http.HTTPRequest].User_Agent.decode()
            else:
                user_agent = 'N/A'

            browser_info = extract_browser_info(user_agent)
            form_data = extract_form_data(packet)

            # Convert form data dictionary to string representation
            form_data_str = "\n".join([f"{key}: {value}" for key, value in form_data.items()])

            # Create a table for each captured request
            table = PrettyTable()
            table.field_names = ["Time", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Method", "Path", "Website", "Browser Info", "Form Data"]
            table.add_row([
                timestamp,
                protocol,
                COLOR_GREEN + src_ip + COLOR_END,
                src_port,
                COLOR_GREEN + dst_ip + COLOR_END,
                dst_port,
                method,
                path,
                host,
                browser_info,
                COLOR_RED + form_data_str + COLOR_END
            ])
            table.align = "l"
            table.title = "Captured HTTP Requests"
            table.align["Form Data"] = "l"
            print(f"{'='*20} New HTTP Request {'='*20}")
            print(table)
            print('='*60)

def main():
    print("Starting website visit and form submission capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, filter="", store=0)

if __name__ == '__main__':
    main()
