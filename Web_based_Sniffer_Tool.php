<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $show_mac = isset($_POST['show_mac']) && $_POST['show_mac'] === 'true' ? "True" : "False";
    $clear_output = isset($_POST['clear_output']) && $_POST['clear_output'] === 'true' ? true : false;

    if ($clear_output) {
        echo "CLEAR_OUTPUT";
        exit;
    }

    $python_script = <<<PYTHON
from scapy.all import sniff, wrpcap, Raw, IP
from scapy.layers.http import HTTPRequest
import datetime
import json
import re

def packet_handler(packet, show_mac):
    current_datetime = datetime.datetime.now().strftime('%Y-%m-%d <green>|</green> %H:%M:%S.%f')
    summary = f"{current_datetime}<green>|</green> {packet.summary()}"

    if show_mac == "True" and packet.haslayer('Ether'):
        src_mac = packet['Ether'].src
        dst_mac = packet['Ether'].dst
        summary += f" <green>|</green> SrcMAC: {src_mac}, DstMAC: {dst_mac}"
    
    if IP in packet:
        protocol = packet[IP].proto
        if protocol == 6:  # TCP
            summary += f" <green>|</green> Protocol: TCP <green>|</green> SrcPort: {packet['TCP'].sport}, DstPort: {packet['TCP'].dport}"
        elif protocol == 17:  # UDP
            summary += f" <green>|</green> Protocol: UDP <green>|</green> SrcPort: {packet['UDP'].sport}, DstPort: {packet['UDP'].dport}"
        else:
            summary += f" <green>|</green> Protocol: {protocol}"
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        summary += f" <green>|</green> Source IP: <green>{src_ip}</green>, Destination IP: <green>{dst_ip}</green>"
    
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        url = http_layer.Host.decode() + http_layer.Path.decode()
        summary += f" <green>|</green> URL: <yellow>{url}</yellow>"
        if packet.haslayer(Raw):
            raw_payload = packet.getlayer(Raw).load.decode(errors='ignore')
            payload_items = re.findall(r'([^&=]+)=([^&]*)', raw_payload)
            if payload_items:
                colored_payload = " ".join([f"<red>{key}</red>={value}" for key, value in payload_items])
                summary += f" <green>|</green> Payload: {colored_payload}"
            else:
                summary += f" <green>|</green> Payload: {raw_payload}"
    
    print(summary)
    wrpcap('captured_packets.pcap', packet, append=True)

sniff(prn=lambda packet: packet_handler(packet, "$show_mac"), count=10, timeout=2)
PYTHON;

    $file = tempnam(sys_get_temp_dir(), 'sniff_');
    file_put_contents($file, $python_script);

    $command = escapeshellcmd("python $file 2>&1");
    exec($command, $output_array, $return_var);

    if ($return_var !== 0) {
        $output = "Error executing the script. Return code: $return_var";
    } else {
        $output = implode("\n", $output_array);
    }

    unlink($file);

    $output = preg_replace([
        '/<red>(.*?)<\/red>/',
        '/<green>(.*?)<\/green>/',
        '/<yellow>(.*?)<\/yellow>/',
        '/<purple>(.*?)<\/purple>/',
    ], [
        '<span style="color: red;">$1</span>',
        '<span style="color: green;">$1</span>',
        '<span style="color: yellow;">$1</span>',
        '<span style="color: purple;">$1</span>',
    ], $output);
    
    echo $output . "\n";
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Packet Sniffer</title>
    <link rel="stylesheet" href="style.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f4f4;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    background-color: #fff;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
}

h1 {
    color: #2c3e50;
    text-align: center;
    margin-bottom: 30px;
}

.info {
    background-color: #ecf0f1;
    padding: 20px;
    border-radius: 5px;
    margin-bottom: 20px;
}

form {
    margin-bottom: 20px;
}

.checkbox-wrapper {
    margin-bottom: 15px;
}

input[type="checkbox"] {
    margin-right: 10px;
}

input[type="submit"] {
    background-color: #3498db;
    color: #fff;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s ease;
    font-size: 16px;
}

input[type="submit"]:hover {
    background-color: #2980b9;
}

pre {
    background-color: #2c3e50;
    color: #ecf0f1;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 14px;
    line-height: 1.4;
}

.message {
    background-color: #e74c3c;
    color: #fff;
    padding: 10px;
    border-radius: 5px;
    text-align: center;
}

.output-container {
    max-height: 300px;
    overflow-y: auto;
    transition: all 0.3s ease;
}

.zoom-toggle {
    display: none;
}

.zoom-label {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background-color: #3498db;
    color: #fff;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s ease;
    font-size: 16px;
    z-index: 1000;
}

.zoom-label:hover {
    background-color: #2980b9;
}

.zoom-toggle:checked + .zoom-label {
    background-color: #e74c3c;
}

.zoom-toggle:checked + .zoom-label::after {
    content: "Close";
}

.zoom-toggle:checked ~ .output-container {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    max-height: none;
    background-color: rgba(0, 0, 0, 0.9);
    z-index: 999;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
    box-sizing: border-box;
}

.zoom-toggle:checked ~ .output-container pre {
    width: 90%;
    height: 90%;
    max-width: none;
    font-size: 18px;
    background-color: #2c3e50;
    color: #ecf0f1;
    padding: 20px;
    border-radius: 5px;
    overflow: auto;
}
.footer {
    text-align: center;
    padding: 20px;
    background-color: #2c3e50;
    color: #ecf0f1;
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
}

.footer p {
    margin: 0;
    font-size: 14px;
}

.footer .heart {
    color: #e74c3c;
    font-size: 18px;
    animation: heartbeat 1s infinite;
}

.footer a {
    color: #3498db;
    text-decoration: none;
    transition: color 0.3s ease;
}

.footer a:hover {
    color: #2980b9;
}

@keyframes heartbeat {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.1); }
}


        .output-container pre span {
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>NETWORK SNIFFER TOOL</h1>
        <div class="info">
            <p>This packet sniffer captures network packets using Python and Scapy, similar to Wireshark.</p>
            <p>Start capturing packets by clicking the button below:</p>
        </div>
        <form id="sniffForm">
            <div class="checkbox-wrapper">
                <input type="checkbox" id="show_mac" name="show_mac">
                <label for="show_mac">Show MAC Addresses</label>
            </div>
            <input type="button" id="startSniffing" value="Start Packet Sniffing" style="background-color: #007bff; color: white; border: none; border-radius: 5px; padding: 10px 20px; font-size: 16px; cursor: pointer; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); transition: background-color 0.3s, box-shadow 0.3s;">
            <input type="button" id="stopSniffing" value="Stop Packet Sniffing" style="background-color: #007bff; color: white; border: none; border-radius: 5px; padding: 10px 20px; font-size: 16px; cursor: pointer; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); transition: background-color 0.3s, box-shadow 0.3s;">
        </form>

        <div class='info'>
            <p>Packet sniffing output:</p>
            <input type='checkbox' id='zoom-toggle' class='zoom-toggle'>
            <label for='zoom-toggle' class='zoom-label'>Zoom</label>
            <div class='output-container'><pre id='sniffing-output'></pre></div>
        </div>

        <footer class="footer">
        <p style="font-size: larger;">Made with <span class="heart" style="font-size: larger;">&#10084;</span> by 
    <a href="https://www.linkedin.com/in/dev-suthar07" target="_blank" rel="noopener noreferrer">Dev Suthar</a>
</p>

        </footer>
    </div>

    <script>
    $(document).ready(function() {
        let isSniffing = false;
        let intervalId;

        $('#startSniffing').click(function() {
            isSniffing = true;
            $('#startSniffing').hide();
            $('#stopSniffing').show();
            clearOutput();
            startSniffing();
        });

        $('#stopSniffing').click(function() {
            isSniffing = false;
            $('#stopSniffing').hide();
            $('#startSniffing').show();
            clearInterval(intervalId);
        });

        function clearOutput() {
            $.ajax({
                url: '<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>',
                method: 'POST',
                data: {
                    clear_output: true
                },
                success: function(response) {
                    if (response.trim() === "CLEAR_OUTPUT") {
                        $('#sniffing-output').empty();
                    }
                }
            });
        }

        function startSniffing() {
            function pollServer() {
                if (!isSniffing) return;

                $.ajax({
                    url: '<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>',
                    method: 'POST',
                    data: {
                        show_mac: $('#show_mac').is(':checked')
                    },
                    success: function(response) {
                        $('#sniffing-output').append(response);
                        if (!$('#zoom-toggle').is(':checked')) {
                            $('#sniffing-output').scrollTop($('#sniffing-output')[0].scrollHeight);
                        }
                        colorizeOutput();
                    },
                    error: function() {
                        console.log('Error occurred while sniffing');
                    }
                });
            }

            intervalId = setInterval(pollServer, 1000); // Poll every 1 second
        }

        function colorizeOutput() {
            $('#sniffing-output').html(function(index, oldHtml) {
                return oldHtml
                    .replace(/<red>(.*?)<\/red>/g, '<span style="color: red;">$1</span>')
                    .replace(/<green>(.*?)<\/green>/g, '<span style="color: green;">$1</span>')
                    .replace(/<yellow>(.*?)<\/yellow>/g, '<span style="color: yellow;">$1</span>')
                    .replace(/<purple>(.*?)<\/purple>/g, '<span style="color: purple;">$1</span>');
            });
        }

        $('#zoom-toggle').change(function() {
            if (this.checked) {
                $('.output-container pre').css('font-size', '20px');
            } else {
                $('.output-container pre').css('font-size', '');
            }
        });
    });
    </script>
</body>
</html>
