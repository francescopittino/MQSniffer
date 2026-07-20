import customtkinter
import re, time, threading
import random
from paho.mqtt import client as mqtt_client
import nmap, socket
import ipaddress
from ipaddress import IPv4Interface
import netifaces
import ctkchart


RANDOM_CLIENT_ID = f'subscribe-{random.randint(0, 100)}'

CONN_THREADS = []

def connect_mqtt(broker, port) -> mqtt_client:
    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            print("Connected to MQTT Broker!")
        else:
            print(f"Failed to connect, return code {reason_code}")

    client = mqtt_client.Client(
        client_id=RANDOM_CLIENT_ID,
        callback_api_version=mqtt_client.CallbackAPIVersion.VERSION2,
    )
    # client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client

def get_default_interface(target: tuple[str, int] | None = None) -> IPv4Interface:
    """Return the network interface used to connect to target."""
    if target is None:
        target = ("8.8.8.8", 80)  # Google DNS server address
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(target)
            ip_address = s.getsockname()[0]
    except Exception as e:
        print(f"Failed to auto-detect IP address: {e}")
        ip_address = "127.0.0.1"  # fallback to localhost
    try:
        for dev in netifaces.interfaces():
            for items in netifaces.ifaddresses(dev).values():
                for item in items:
                    if item["addr"] == ip_address:
                        return IPv4Interface(f"{ip_address}/{item['mask']}")
    except Exception as e:
        print(f"Failed to auto-detect network interface: {e}")
    return IPv4Interface("127.0.0.1/24")  # fallback to localhost

def mask_to_prefix(mask_str):
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask_str}", strict=False)
        return network.prefixlen
    except ValueError as e:
        raise ValueError(f"Invalid subnet mask: {e}")

def get_network_address(ip_str, prefix_length):
    try:
        network = ipaddress.ip_network(f"{ip_str}/{prefix_length}", strict=False)
        return str(network.network_address)
    except ValueError as e:
        raise ValueError(f"Invalid IP or prefix length: {e}")

def scan_network(network_range):
    nm = nmap.PortScanner()  
    # Scan subnet: -sn = no port scan (host discovery), -PE = ICMP echo (ping)  
    nm.scan(hosts=network_range, arguments='-sn -PR') 
    print("Running: ", nm.command_line()) 
 
    devices = []  
    for host in nm.all_hosts():  
        hostname = nm[host].hostname() or 'unknown'  
        devices.append({  
            'ip': host,  
            'hostname': hostname,  
            'status': nm[host].state()  
        })  
    return devices  


def checkBroker(_frame, _dest):
    print(_dest)
    print(f"Trying to connect to: {_dest["ip"]}:1883")
    try:
        item_client = connect_mqtt(_dest["ip"], 1883)
        item_client.loop_start()
        time.sleep(2)
        item_client.disconnect()
        item_client.loop_stop()
        print(f"{_dest["ip"]}:1883 found as valid broker")
        _frame._add_broker_subframe_(_dest["hostname"], _dest["ip"], "1883")
    except:
        print(f"{_dest["ip"]}:1883 is not a broker")

def startAutoSearch(broker_frame):
    #examine local network for possible mqtt brokers and try to connect (and disconnect)
    #If connection is possible, save them in the list. If connection is not possible, they will not be listed in the scrollableFrame
    my_ip = get_default_interface()
    broker_frame._delete_items_()
    if(my_ip != "127.0.0.1/24"):
        ip_pfix = my_ip.with_netmask.split("/")
        p_length = mask_to_prefix(ip_pfix[1])
        network = get_network_address(ip_pfix[0], p_length)
        net_with_mask = network+"/"+str(p_length)
        print("Network: " , net_with_mask)
        result_list = scan_network(net_with_mask)
        exploration_threads = []
        for item in result_list:
            t  = threading.Thread(target = checkBroker, args=(broker_frame, item))
            exploration_threads.append(t)
            t.start()
        for t in exploration_threads:
            t.join(timeout=5) #wait for the search to finish
        print("End of Search!")
    else:
        broker_frame._add_broker_subframe_("WARNING", "NETWORK", "ERROR")

def subscribe(client: mqtt_client, topic, frame, _ip, _port, _hostname):
    def on_message(client, userdata, msg):
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
        frame._new_message_(_ip, _port, _hostname, msg.topic, msg.payload.decode())


    client.subscribe(topic)
    client.on_message = on_message

def start_client(_ip, _port, _hostname, frame, topic="#"):
    print(f"Trying to connect to: {_ip}:{str(_port)}")
    try:
        client = connect_mqtt(_ip, _port)
        subscribe(client, topic, frame, _ip, _port, _hostname)
        client.loop_forever()
    except Exception as e:
        print("Error in connecting to broker")
        print(e)

    
def subscribeToAllTopics(_gui, _ip, _port, _hostname):
    new_client_thread = threading.Thread(target = start_client, args=(_ip, _port, _hostname, _gui.topics_scrollframe, "#"), daemon=True)
    CONN_THREADS.append(new_client_thread)
    new_client_thread.start()



class BrokersFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, main_gui, **kwargs):
        super().__init__(master, **kwargs)
        self.item_list = []
        self.button_list = []
        self.main_gui = main_gui

    def _add_broker_subframe_(self, _hostname, _ip, _port):
        new_item = customtkinter.CTkLabel(self, text = f'{_ip}:{_port}')
        new_item_hostname = customtkinter.CTkLabel(self, text = f'{_hostname}')
        new_item_button = customtkinter.CTkButton(self, text = "Add all topics from this broker", command = lambda: subscribeToAllTopics(self.main_gui, _ip, int(_port), _hostname))
        new_item_hostname.grid(row = len(self.item_list), column = 0, padx = 10, pady = (0,10))
        new_item.grid(row = len(self.item_list), column=1, pady=(0, 10))
        new_item_button.grid(row = len(self.item_list), column = 2, padx=100, pady=(0,10))
        self.item_list.append(new_item)
        self.button_list.append(new_item_button)

    def _delete_items_(self):
        for item in self.item_list:
            item.destroy()
        for item in self.button_list:
            item.destroy()
        self.item_list = []
        self.button_list = []

class TopicsFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.item_list = []
        
    def _add_topics_subframe_(self, _hostname, _ip, _port, _topic, is_int):
        new_frame = customtkinter.CTkFrame(master = self, width=800, height=200, corner_radius=0, fg_color="transparent")
        new_frame_host_label = customtkinter.CTkLabel(master=new_frame, text=f'{_topic} ({_hostname})')
        new_frame_addr_label = customtkinter.CTkLabel(master=new_frame, text=f'{_ip}:{str(_port)}')
        new_frame_textbox = customtkinter.CTkTextbox(master=new_frame)
        new_frame_textbox.configure(state="disabled")
        #graph
        if(is_int):
            chart = ctkchart.CTkLineChart(master = new_frame, x_axis_values = (1, 2, 3), y_axis_values = (-10, 50))
            chart_line = ctkchart.CTkLine(master = chart)
        #positioning
        new_frame.pack()
        new_frame_host_label.grid(row = 0, column = 0, padx = 10, pady = 10)
        new_frame_addr_label.grid(row = 0, column = 1, padx = 10, pady = 10)
        new_frame_textbox.grid(row = 1, column = 0, padx = 10, pady = 10)
        chart.grid(row = 1, column = 1, padx = 10, pady = 10)
        if(is_int):
            _plot = chart
            _line = chart_line
        else:
            _plot = None
            _line = None
        self.item_list.append({"frame":new_frame, "hostname":_hostname, "ip":_ip, "port":_port, "topic":_topic, "is_int": is_int, "plot": _plot, "line": _line, "textbox":new_frame_textbox})

    def _new_message_(self, _ip, _p, _hostname, _topic, message):
        found = False
        _port = str(_p)
        for existing_frame in self.item_list:
            if(existing_frame["ip"]==_ip and existing_frame["port"]==str(_port) and existing_frame["topic"]==_topic):
                #add new value to textbox
                existing_frame["textbox"].configure(state="normal")
                existing_frame["textbox"].insert("end", message+"\n")
                existing_frame["textbox"].configure(state="disabled")
                existing_frame["textbox"].see("end")
                #update chart
                if(existing_frame["is_int"]):
                    existing_frame["plot"].show_data(line = existing_frame["line"], data = [float(message)])
                found = True
        if(not found):
            try:
                float(message)
                is_int = True
            except:
                is_int = False
            self._add_topics_subframe_(_hostname, _ip, _port, _topic, is_int)
            for existing_frame in self.item_list:
                if(existing_frame["ip"]==_ip and existing_frame["port"]==str(_port) and existing_frame["topic"]==_topic):
                    existing_frame["textbox"].configure(state="normal")
                    existing_frame["textbox"].insert("end", message+"\n")
                    existing_frame["textbox"].configure(state="disabled")
                    existing_frame["textbox"].see("end")

class AppGui(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("MQSniffer")
        self.geometry("900x600")
        self.resizable(False, False)

        #create TABVIEW
        self.tabview = customtkinter.CTkTabview(master = self, width = 900, height = 600)
        self.tabview.grid(row = 0, column = 0)

        #create TAB: Network Brokers
        network_tab = self.tabview.add("Add Brokers")
        self.net_brokers_frame = BrokersFrame(master = network_tab, main_gui = self, width = 850, height = 500, corner_radius=0, fg_color="transparent") #scrollable frame for brokers
        self.net_auto_search_button = customtkinter.CTkButton(network_tab, text = "Start Auto-Search", 
                                                              command = lambda: startAutoSearch(self.net_brokers_frame))
        self.net_auto_search_button.grid(row = 0, column = 0, sticky = "nsew")
        self.net_brokers_frame.grid(row=1, column=0, sticky="nsew")

        #create TAB: Topics
        topics_tab = self.tabview.add("All Subscriptions")
        self.topics_title_label = customtkinter.CTkLabel(topics_tab, text = "Your Topics:")
        self.topics_title_label.grid(row = 0, column = 0)
        self.topics_scrollframe = TopicsFrame(master = topics_tab, width = 850, height = 500, corner_radius=0, fg_color="transparent")
        self.topics_scrollframe.grid(row=1, column=0, sticky="nsew")

    #getter for scrollframe (TOPICS)
    def get_topics_scrollframe(self):
        return self.topics_scrollframe


def _main_window_():
    app = AppGui()
    app.mainloop()

_main_window_()