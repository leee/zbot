import datetime
import logging
import moira
import os
import Queue
import random
import select
import signal
import subprocess
import sys
import threading
import time
import zephyr

SHUTDOWN = False

classes = ['cela', 'hpt', 'leee', 'leee-test', 'pranjal']

kprinc = "daemon/leee.mit.edu"
krealm = "ATHENA.MIT.EDU"
keytab = "/mit/leee/cron_scripts/daemon.leee.keytab"

zephyr_from_q = Queue.Queue()
zephyr_send_q = Queue.Queue()

def zreply(z, body):
    r = zephyr.ZNotice()
    r.cls = z.cls
    r.instance = z.instance
    # personal iff recipient isn't empty and doesn't begin with a @
    if z.recipient and not z.recipient.startswith("@"):
        r.recipient = z.sender
        r.sender = z.recipient
    else:
        r.sender = kprinc
    r.opcode = 'auto'
    r.fields = [kprinc, body]
    zephyr_send_q.put(r)

def module_fmk(option, z, listname):
    try:
        moira.connect()
        mem = moira.query('get_end_members_of_list', listname)
        mem = [d for d in mem if d.get('member_type') in ['USER', 'LIST', 'KERBEROS', 'STRING', 'MACHINE']]
        if len(mem) < 3:
            zreply(z, "Not enough members on LIST " + listname)
        else:
            if option == "fmk":
                body = ["Who would you fuck, marry, kill?"]
            elif option == "hpt":
                body = ["Who would you hack, punt, tool with?"]
            for d in random.sample(mem, 3):
                body.append("- " + d.get('member_type') + " " + d.get('member_name'))
            zreply(z, "\n".join(body))
    except moira.MoiraException as e:
        if e.code == moira.errors()['MR_LIST']:
            zreply(z, listname + " is not a list.")
        elif e.code == moira.errors()['MR_PERM']:
            zreply(z, "Insufficient permission for lIST " + listname)

def module_hunt(options, z):
    tn = time.time()
    ts = time.mktime(datetime.datetime(2017, 1, 13, 12, 0, 0).timetuple())
    td = ts - tn
    ta = abs(td)
    m, s = divmod(ta, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    s = str(int(s))
    m = str(int(m))
    h = str(int(h))
    d = str(int(d))
    if options == "q":
        if td > 0:
            zreply(z, "NO! " + d + " days, " + h + " hours, " + m + " minutes, and " + s + " seconds until hunt.")
        else:
            zreply(z, "YES! " + d + " days, " + h + " hours, " + m + " minutes, and " + s + " seconds has elapsed.")
    else:
        if td > 0:
            zreply(z, d + " days, " + h + " hours, " + m + " minutes, and " + s + " seconds until hunt.")
        else:
            zreply(z, "HUNT HUNT HUNT HUNT! " + d + " days, " + h + " hours, " + m + " minutes, and " + s + " seconds has elapsed.")

def magic_word(z, word):
    return z.fields[1].startswith(word)

def tool():
    while not SHUTDOWN:
        while True:
            try:
                z = zephyr_from_q.get(False)
            except Queue.Empty:
                break
            if z.opcode.lower() not in ('ping', 'auto'):
                query = z.fields[1].lower().split()
                if query[0] == "hpt" and len(query) == 2:
                    module_fmk("hpt", z, query[1])
                if query[0] == "fmk" and len(query) == 2:
                    module_fmk("fmk", z, query[1])
                if query[1] == "hpt" and len(query) == 3:
                    module_fmk("hpt", z, query[2])
                if query[1] == "fmk" and len(query) == 3:
                    module_fmk("fmk", z, query[2])
                if query[0] == "hunt" and query[1:] == query[:-1]:
                    module_hunt("", z)
                if query == ["is", "it", "hunt", "yet"]:
                    module_hunt("q", z)

def zephyr_send():
    while not SHUTDOWN:
        while True:
            try:
                z = zephyr_send_q.get(False)
            except Queue.Empty:
                break
            logging.debug(
                "[ZEPHYR] [SEND] %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                z.kind, z.cls, z.instance, z.time, z.port, z.auth, z.recipient,
                z.sender, z.opcode, z.format, z.other_fields, z.fields)
            z.send()

def zephyr_from():
    subs = zephyr.Subscriptions()
    for c in classes:
        logging.info("Subscribing to: " + c)
        subs.add((c, '*', ''))
    while not SHUTDOWN:
        z = zephyr.receive(False)
        if z:
            logging.debug(
                "[ZEPHYR] [FROM] %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                z.kind, z.cls, z.instance, z.time, z.port, z.auth, z.recipient,
                z.sender, z.opcode, z.format, z.other_fields, z.fields)
            zephyr_from_q.put(z)
        else:
            select.select([zephyr._z.getFD()], [], [], 1)

def kinit():
    os.system("kinit " + kprinc + "@" + krealm + " -kt " + keytab)
    logging.debug("[KERBEROS] klist\n" +
                                    subprocess.Popen(['klist'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE).stdout.read())
    logging.info("[KERBEROS] kinit " + kprinc + "@" + krealm + " -kt " + keytab)

def krb():
    next_kinit = time.time()
    while not SHUTDOWN:
        if time.time() > next_kinit:
            kinit()
            next_kinit = time.time() + 3600
            logging.info("[KERBEROS] next kinit in 3600s")

def main():
    global SHUTDOWN

    logging.basicConfig(level = logging.DEBUG,
        format = "[%(asctime)-15s] %(levelname)s:%(name)s: %(message)s")

    kinit()
    zephyr.init()

    thread_krb = threading.Thread(target = krb)
    thread_zephyr_send = threading.Thread(target = zephyr_send)
    thread_zephyr_from = threading.Thread(target = zephyr_from)
    thread_tool = threading.Thread(target = tool)

    threads = [thread_krb, thread_zephyr_send, thread_zephyr_from, thread_tool]
    for t in threads:
        t.start()

    while True:
        try:
            signal.pause()
        except (KeyboardInterrupt, SystemExit):
            break
    SHUTDOWN = True

    for t in threads:
        t.join()

    return 0

if __name__ == '__main__':
    sys.exit(main())
