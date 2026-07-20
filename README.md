# MQSniffer
Small project I used to learn more about the MQTT Protocol. Automatically finds and tracks multiple brokers in the local net and provides graphs for suitable values.
Currently it's bare bones...

Requires:
-customtkinter and ctkchart
-paho-mqtt
-nmap, netifaces2 and ipaddress

The Brokers tab allows you to auto-search brokers on default port (1883) on the local net, then add all topics from them to your subscriptions:
<img width="672" height="473" alt="broker" src="https://github.com/user-attachments/assets/603cd989-e05f-4773-9843-87993bdaa231" />

The Subscriptions tab allows you to see the data received on all subbed topics and the relevant plots if possible:
<img width="667" height="464" alt="subs" src="https://github.com/user-attachments/assets/2edf1b34-e5b4-4ab6-b078-cf3fe582a102" />

Future Plans:
-Add option to connect to a broker by user input (ip and port)
-Add option to subscribe to only a given topic
-Refine user interface
-General improvements and additional (less important) options
