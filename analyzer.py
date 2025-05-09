import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP
import threading

root = tk.Tk()
root.title('Network Packet Analyzer')
root.geometry('800x600')

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

vsb = tk.Scrollbar(frame, orient='vertical')
vsb.pack(side='right', fill='y')

hsb = tk.Scrollbar(frame, orient='horizontal')
hsb.pack(side='bottom', fill='x')


tree = ttk.Treeview(frame, columns=("S/N", "Source IP", "Destination IP", "Protocol", "Length"),
                    yscrollcommand=vsb.set,
                    xscrollcommand=hsb.set)

vsb.config(command=tree.yview)
hsb.config(command=tree.xview)

tree.column('#0', width=0, stretch=tk.NO)
tree.column('S/N', anchor='w', width= 50)
tree.column('Source IP',  anchor='nw', width= 200)
tree.column('Destination IP',  anchor='n', width= 200)
tree.column('Protocol',  anchor='ne', width= 100)
tree.column('Length',  anchor="e", width= 100)

tree.heading('S/N',text= 'S/N' )
tree.heading("Source IP",text= 'Source IP')
tree.heading("Destination IP", text= 'Destination IP')
tree.heading("Protocol", text="Protocol")
tree.heading("Length", text="Length")


count = 0
capturing = True

def capture_packets():
    global count, capturing
    def packet_callback(packet):
        global count
        print("capturing started.....")
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet.proto
            length = len(packet)

            tree.insert('', 'end', values=(count, source_ip, dest_ip, protocol, length))
            count += 1


    def sniff_packets():
        print("Capturing started...")
        sniff(iface="en0", prn=packet_callback, store=0)

  
    threading.Thread(target=sniff_packets, daemon=True).start()


def stop_capturing():
   global capturing
   capturing = False
   print('Capturing Stopped..')
    


tree.pack(side='left', fill=tk.BOTH, expand=True)



start = tk.Button(root, text='Start Capture', command=capture_packets)
start.pack(pady=10)

stop = tk.Button(root, text="Stop Capture", command=stop_capturing)
stop.pack(pady=10)

if __name__ == "__main__":
    root.mainloop()