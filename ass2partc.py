import socket
import random
import sys

HEADER_NO_ID = "01 00 00 01 00 00 00 00 00 00"
A = 1
CNAME = 5
PTR = 12
MX = 15
AAAA = 28
QCLASS = "00 01"

DNS_ADDRESS = "8.8.8.8"
# DNS_ADDRESS = "130.102.71.160"
DNS_PORT = 53

HEX_FORMAT = 16

REVERSE_DNS = ".in-addr.arpa"

MIN_POINTER_VALUE = 192


def generate_id() -> str:
    new_id = ""
    for i in range(4):
        new_id += str(random.randrange(0, 9))

    return new_id


def hex_string(num: int, padding: int):
    return "{0:0{1}x}".format(num, padding)


def normal_query(url: str) -> str:
    qname = ""
    for label in url.split("."):
        length = hex_string(len(label), 2)
        ascii_url = ""
        for char in label:
            ascii_url += hex_string(ord(char), 2)

        qname += length + ascii_url

    qname += "00"

    return qname


def compose_request(request_id: str, url: str, current_qtype: int) -> str:
    # url_ascii = url.encode("ascii")
    # bytes(bytearray.fromhex(hex_string))

    # HEADER
    header = request_id + HEADER_NO_ID.replace(" ", "")

    # QUERY
    if current_qtype == PTR:
        url = reverse_query(url)

    qname = normal_query(url)

    qtype = hex_string(current_qtype, 4)

    query = qname + qtype + QCLASS.replace(" ", "")

    return header + query


def reverse_query(ip: str) -> str:
    parts = ip.split(".")

    # for i, part in enumerate(parts):
    #     parts[i] = part[::-1]

    flipped_ip = ".".join(reversed(parts))
    flipped_ip += REVERSE_DNS

    return flipped_ip


def send_udp_message(message: str, dns_server: str) -> str:
    server_address = (dns_server, DNS_PORT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # result = ""
    try:
        byte_message = bytes.fromhex(message)
        sock.sendto(byte_message, server_address)
        data, _ = sock.recvfrom(4096)
        result = data.hex()
    except socket.error:
        print("not good")
        sys.exit()
    finally:
        sock.close()

    return result


def check_response(response: str, actual_id: str) -> int:
    response_id = response[0:4]

    if response_id != actual_id:
        return -1

    num_answers = response[12:16]

    return int(num_answers, HEX_FORMAT)


def parse_response_ipv4(response: str, start_index: int) -> tuple:
    end_index = start_index + 4
    data_length = int(response[start_index:end_index], HEX_FORMAT)
    num_hex = 2 * data_length

    result = []
    for i in range(end_index, end_index + num_hex, 2):
        current_hex_string = response[i] + response[i + 1]
        result.append(str(int(current_hex_string, HEX_FORMAT)))

    string_result = ".".join(result)
    return string_result, num_hex


def parse_response_ipv6(response: str, start_index: int) -> tuple:
    end_index = start_index + 4
    data_length = int(response[start_index:end_index], HEX_FORMAT)
    num_hex = 2 * data_length

    result = []
    for i in range(end_index, end_index + num_hex, 4):
        current_hex_string = response[i:i+4]
        if current_hex_string == "0000":
            current_hex_string = "0"
        else:
            current_hex_string = current_hex_string.lstrip("0")

        result.append(current_hex_string)

    i = 0
    final = []
    while i < len(result):
        if i < len(result) - 1 and result[i] == "0" and result[i + 1] == "0":
            final.append("")
            while result[i + 1] == "0":
                i += 1
        else:
            final.append(result[i])

        i += 1

    string_result = ":".join(final)

    return string_result, num_hex


def parse_response_reverse(response: str, start_index: int) -> tuple:
    end_index = start_index + 4
    data_length = int(response[start_index:end_index], HEX_FORMAT)
    num_hex = 2 * data_length

    result = []
    current_word = ""
    bytes_to_read = 0
    bytes_read = 0
    for i in range(end_index, end_index + num_hex, 2):
        current_hex_string = response[i:i+2]
        if bytes_read < bytes_to_read:
            letter = bytes.fromhex(current_hex_string).decode()
            current_word += letter
            bytes_read += 1
        else:
            bytes_to_read = int(current_hex_string, HEX_FORMAT)
            bytes_read = 0
            if i != end_index:
                result.append(current_word)
                current_word = ""

    return ".".join(result), num_hex


def follow_pointer(response: str, offset: int) -> str:
    result = []
    while True:
        current = response[offset:offset + 2]
        size = int(current, HEX_FORMAT)

        if size >= MIN_POINTER_VALUE:
            new_offset = int(response[offset + 2: offset + 4], HEX_FORMAT) * 2
            current_word = follow_pointer(response, new_offset)
            result.append(current_word)
            break

        elif size == 0:
            break

        offset += 2
        current_hex_string = response[offset:offset + (size * 2)]
        current_word = bytes.fromhex(current_hex_string).decode()
        result.append(current_word)

        offset += (size * 2)

    return ".".join(result)


def parse_response_mail(response: str, response_only: str, start_index: int):
    end_index = start_index + 4
    data_length = int(response_only[start_index:end_index], HEX_FORMAT)
    num_hex = 2 * data_length

    preference_length = 4

    result = []
    counter = num_hex - preference_length
    index = end_index + preference_length
    while counter > 0:
        size = int(response_only[index:index + 2], HEX_FORMAT)

        if size >= MIN_POINTER_VALUE:
            offset = int(response_only[index + 2: index + 4], HEX_FORMAT) * 2
            current_word = follow_pointer(response, offset)
            result.append(current_word)
            break

        index += 2
        current_hex_string = response_only[index:index + (size * 2)]
        current_word = bytes.fromhex(current_hex_string).decode()
        result.append(current_word)

        index += (size * 2)
        counter -= 2 - (size * 2)

    return ".".join(result), num_hex


def parse_response_canonical(response: str, response_only: str, start_index: int) -> tuple:
    end_index = start_index + 4
    data_length = int(response_only[start_index:end_index], HEX_FORMAT)
    num_hex = 2 * data_length

    result = []
    counter = num_hex
    index = end_index
    while counter > 0:
        size = int(response_only[index:index + 2], HEX_FORMAT)

        if size >= MIN_POINTER_VALUE:
            offset = int(response_only[index + 2: index + 4], HEX_FORMAT) * 2
            current_word = follow_pointer(response, offset)
            result.append(current_word)
            break

        index += 2
        current_hex_string = response_only[index:index + (size * 2)]
        current_word = bytes.fromhex(current_hex_string).decode()
        result.append(current_word)

        index += (size * 2)
        counter -= 2 - (size * 2)

    return ".".join(result), num_hex


def get_type(message: str, start_index: int) -> int:
    type_index = start_index + 4
    qtype = message[type_index:type_index + 4]

    return int(qtype, HEX_FORMAT)


def process_request(url: str, request_type: int, dns_server: str) -> list:
    ips = []

    request_id = generate_id()

    message = compose_request(request_id, url, request_type)

    response = send_udp_message(message, dns_server)

    answers = check_response(response, request_id)
    if answers == -1:
        print("oh dear")

    response_only = response[len(message):]
    current_answer_index = 0
    length = 0
    for i in range(answers):
        answer_type = get_type(response_only, current_answer_index)
        if answer_type == A:
            data, length = parse_response_ipv4(response_only, current_answer_index + 20)
            ips.append(data)
        elif answer_type == AAAA:
            data, length = parse_response_ipv6(response_only, current_answer_index + 20)
            ips.append(data)
        elif answer_type == PTR:
            data, length = parse_response_reverse(response_only, current_answer_index + 20)
            ips.append(data)
        elif answer_type == MX:
            data, length = parse_response_mail(response, response_only, current_answer_index + 20)
            ips.append(data)
        elif answer_type == CNAME:
            data, length = parse_response_canonical(response, response_only, current_answer_index + 20)
            if request_type == CNAME:
                ips.append(data)

        current_answer_index += (4 * 6) + length

    return ips


def dns_lookup(url: str, dns_server: str, reverse: bool):
    result = {}

    if reverse:
        url = process_request(url, PTR, dns_server)[0]

    result["hostname"] = url
    result["ipv4"] = process_request(url, A, dns_server)
    result["ipv6"] = process_request(url, AAAA, dns_server)
    result["mail"] = process_request(url, MX, dns_server)
    result["canonical"] = process_request(url, CNAME, dns_server)

    return result


def main():
    # print(process_request("remote.labs.eait.uq.edu.au", A, socket.AF_INET))
    # dns_server = "130.102.71.160"
    dns_server = "8.8.8.8"
    url = "manna.eait.uq.edu.au"

    print("Host name: " + url + "\n")
    ipv4 = process_request(url, A, dns_server)
    print("IPv4 Address(es):")
    for ip4 in ipv4:
        print(ip4)

    print("")

    ipv6 = process_request(url, AAAA, dns_server)
    print("IPv6 Address(es):")
    for ip6 in ipv6:
        print(ip6)

    print("")

    print("Reverse DNS Host Name:")
    for host_name in process_request("130.102.79.33", PTR, dns_server):
        # manna -> "130.102.79.33"
        print(host_name)

    print("")

    print("Mail Servers:")
    mx = process_request(url, MX, dns_server)
    for mail_server in mx:
        print(mail_server)

    print("")

    print("Canonical Host Name")
    cname = process_request(url, CNAME, dns_server)
    for canonical in cname:
        print(canonical)


if __name__ == "__main__":
    main()
