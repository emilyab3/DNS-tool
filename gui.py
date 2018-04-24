import tkinter as tk
from tkinter import *
from ass2partc import dns_lookup


class Application(tk.Frame):

    def __init__(self, parent):
        super().__init__(parent)

        # ENTRY SECTION

        main_label = tk.Label(self, text='DNS Tool', font=("Times", 18, "bold"))
        main_label.grid(row=0, columnspan=3, sticky="nsew", padx=5, pady=5)

        # ENTER HOSTNAME/IP ADDRESS

        hostname_label = tk.Label(self, text='Enter a hostname or IPv4 address:')
        hostname_label.grid(row=1, column=0, sticky="e", padx=5, pady=5)

        self._enter_hostname = tk.Entry(self)
        self._enter_hostname.grid(row=1, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        # ENTER DNS SERVER IP ADDRESS

        dns_server_label = tk.Label(self, text='DNS Server:')
        dns_server_label.grid(row=2, column=0, sticky="e", padx=5, pady=5)

        self._enter_dns = tk.Entry(self)
        self._enter_dns.insert(0, "8.8.8.8")
        self._enter_dns.grid(row=2, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        # SELECT NORMAL OR REVERSE DNS LOOKUP

        self._reverse = tk.IntVar()
        self._select_reverse = tk.Checkbutton(self, text='Reverse DNS query', variable=self._reverse)
        self._select_reverse.grid(row=1, column=2, padx=5, pady=5)

        # SUBMIT REQUEST

        self._submit_button = tk.Button(self, text="Submit", command=self.click_submit)
        self._submit_button.grid(row=2, column=2, padx=5, pady=5, ipadx=10, ipady=5)

        # RESULTS SECTION

        results_label = tk.Label(self, text='Results', font=("Times", 16))
        results_label.grid(row=3, columnspan=3, sticky="nsew", padx=5, pady=5)

        # DISPLAY HOSTNAME

        hostname_result = tk.Label(self, text="Host name:")
        hostname_result.grid(row=4, column=0, sticky="e", padx=5, pady=5)

        # self._hostname_text = tk.Entry(self)
        # self._hostname_text.config(state='disabled')
        # self._hostname_text.grid(row=4, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        self._hostname_text = tk.Label(self)
        self._hostname_text.grid(row=4, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        # DISPLAY CANONICAL NAME

        canonical_name = tk.Label(self, text="Canonical name:")
        canonical_name.grid(row=5, column=0, sticky="e", padx=5, pady=5)

        # self._canonical_text = tk.Entry(self)
        # self._canonical_text.config(state='disabled')
        # self._canonical_text.grid(row=5, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        self._canonical_text = tk.Label(self)
        self._canonical_text.grid(row=5, column=1, sticky="nsew", padx=5, pady=5, ipadx=5, ipady=5)

        # DISPLAY IPV4 ADDRESSES

        ipv4_label = tk.Label(self, text="Ipv4 Address(es)")
        ipv4_label.grid(row=6, column=0, padx=5, pady=5, ipadx=5, ipady=5)

        ipv4_frame = tk.Frame(self, height=250, width=250)
        ipv4_frame.columnconfigure(0, weight=10)
        ipv4_frame.grid_propagate(False)
        ipv4_frame.grid(row=7, column=0, padx=15, pady=15)

        self._ipv4_addresses = tk.Text(ipv4_frame)
        self._ipv4_addresses.config(font=("Helvetica", 9))
        self._ipv4_addresses.config(state="disabled")
        self._ipv4_addresses.grid()

        # DISPLAY IPV6 ADDRESSES

        ipv6_label = tk.Label(self, text="Ipv6 Address(es)")
        ipv6_label.grid(row=6, column=1, padx=5, pady=5, ipadx=5, ipady=5)

        ipv6_frame = tk.Frame(self, height=250, width=250)
        ipv6_frame.columnconfigure(0, weight=10)
        ipv6_frame.grid_propagate(False)
        ipv6_frame.grid(row=7, column=1, padx=15, pady=15)

        self._ipv6_addresses = tk.Text(ipv6_frame)
        self._ipv6_addresses.config(font=("Helvetica", 9))
        self._ipv6_addresses.config(state="disabled")
        self._ipv6_addresses.grid()

        # DISPLAY MAIL SERVERS

        mail_label = tk.Label(self, text="Mail Server(s)")
        mail_label.grid(row=6, column=2, padx=5, pady=5, ipadx=5, ipady=5)

        mail_frame = tk.Frame(self, height=250, width=250)
        mail_frame.columnconfigure(0, weight=10)
        mail_frame.grid_propagate(False)
        mail_frame.grid(row=7, column=2, padx=15, pady=15)

        self._mail_servers = tk.Text(mail_frame)
        # scrollbar = tk.Scrollbar(mail_frame)
        # self._mail_servers.config(yscrollcommand=scrollbar.set)
        # scrollbar.config(command=self._mail_servers.yview)
        self._mail_servers.config(font=("Helvetica", 9))
        self._mail_servers.config(state="disabled")
        self._mail_servers.grid()
        # scrollbar.grid(row=0, column=1)

    @staticmethod
    def set_text(name, new):
        name.config(state="normal")
        name.delete(1.0, END)
        name.insert(END, new)
        name.config(state="disabled")

    def click_submit(self):
        url = self._enter_hostname.get()
        dns_server = self._enter_dns.get()
        reverse = self._reverse.get()
        result = dns_lookup(url, dns_server, reverse)

        hostname = result["hostname"]
        self._hostname_text.config(text=hostname)

        canonical = result["canonical"]
        if not canonical:
            canonical_text = "N/A"
        else:
            canonical_text = canonical[0]
        self._canonical_text.config(text=canonical_text)

        ipv4_addresses = result["ipv4"]
        ipv4_text = ""
        for ipv4 in ipv4_addresses:
            ipv4_text += ipv4 + "\n"
        self.set_text(self._ipv4_addresses, ipv4_text)

        ipv6_addresses = result["ipv6"]
        ipv6_text = ""
        for ipv6 in ipv6_addresses:
            ipv6_text += ipv6 + "\n"
        self.set_text(self._ipv6_addresses, ipv6_text)

        mail_servers = result["mail"]
        mail_text = ""
        for mail in mail_servers:
            mail_text += mail + "\n"
            mail_result = dns_lookup(mail, dns_server, False)
            for mail_ipv4 in mail_result["ipv4"]:
                mail_text += "      " + mail_ipv4 + "\n"
            for mail_ipv6 in mail_result["ipv6"]:
                mail_text += "      " + mail_ipv6 + "\n"
        self.set_text(self._mail_servers, mail_text)


class DNSApp(object):

    def __init__(self, master):
        self.master = master
        master.title('DNS Reader')

        application = Application(master)
        application.grid(sticky="nsew", padx=10, pady=10)


def main():
    root = tk.Tk()
    root.resizable(width=False, height=False)
    DNSApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
