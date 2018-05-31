import time
import requests
from string import Template
from netmiko import ConnectHandler
import textfsm
from netmiko import redispatch
import csv
from Utils.Variables import *
import errno
import os
import logging
import logging.handlers
import urllib3
from datetime import datetime
from Utils import templates as t1
import json

urllib3.disable_warnings()
report = []
parsed_dict = {}
cpe_logger = ""
cpe_logger_dict ={}

currtime = str(datetime.now())
currtime =  currtime.replace(" ", "_").replace(":", "_").replace("-", "_").replace(".", "_")

if __name__ == "__main__":
    fileDir = os.path.dirname(os.path.dirname(os.path.realpath('__file__')))
else:
    fileDir = os.path.dirname(os.path.realpath('__file__'))

logfile_dir = fileDir + "/LOGS/" + currtime + "/"
if not os.path.exists(os.path.dirname(logfile_dir)):
    try:
        os.mkdir(os.path.dirname(logfile_dir))
    except OSError as exc:  # Guard against race condition
        if exc.errno != errno.EEXIST:
            raise

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
formatter1 = logging.Formatter("%(message)s")
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter1)
logging.getLogger('').addHandler(console)


def setup_logger(name, filename, level=logging.INFO, state = "MAIN"):
    log_file = logfile_dir + filename  + ".log"
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger = logging.getLogger(name)
    return logger

main_logger = setup_logger('Main', 'UpgradeVersaCpes')


def do_checks(state = "before_upgrade"):
    global report, cpe_list, cpe_logger,cpe_logger_dict
    netconnect = make_connection(vd_ssh_dict)
    for i, rows in cpe_list.iterrows():
        cpe_name = cpe_list.ix[i, 'device_name_in_vd']
        cpe_ip = cpe_list.ix[i, 'ip']
        if state == "before_upgrade":
            cpe_logger = setup_logger(cpe_name, cpe_name + "_upgrade", state = state)
            cpe_logger_dict[cpe_name] = cpe_logger
        else:
            cpe_logger = cpe_logger_dict[cpe_name]
        main_logger.info("<>" * 50)
        main_logger.info(state + " Actions for : " + cpe_name)
        main_logger.info("<>" * 50)
        check_status = check_device_status(netconnect, cpe_name, cpe_ip, state)
        if check_status != "PASS":
            main_logger.info(check_status)
            cpe_result = [cpe_name, check_status]
            report.append(cpe_result)
            cpe_list = cpe_list.drop(index=i)
            continue
        else:
            main_logger.info(cpe_name + " is in sync with VD & able to ping & connect")
    close_connection(netconnect)


def do_cross_connection(vd_ssh_dict, dev_dict):
    global cpe_logger
    netconnect = make_connection(vd_ssh_dict)
    netconnect.write_channel("ssh " + dev_dict["username"] + "@" + dev_dict["ip"] + "\n")
    time.sleep(5)
    output = netconnect.read_channel()
    main_logger.info(output)
    if 'assword:' in output:
        netconnect.write_channel(dev_dict["password"] + "\n")
        output = netconnect.read_channel()
        main_logger.info(output)
    elif 'yes' in output:
        print "am in yes condition"
        netconnect.write_channel("yes\n")
        output = netconnect.read_channel()
        main_logger.info(output)
        time.sleep(1)
        netconnect.write_channel(dev_dict["password"] + "\n")
        output = netconnect.read_channel()
        main_logger.info(output)
    else:
        # cpe_logger.info(output)
        return "VD to CPE " + dev_dict["ip"] + "ssh Failed."
    netconnect.write_channel("cli\n")
    output1 = netconnect.read_channel()
    main_logger.info(output1)
    time.sleep(2)
    try:
        main_logger.info("doing redispatch")
        redispatch(netconnect, device_type='versa')
    except ValueError as Va:
        main_logger.info(Va)
        main_logger.info("Not able to get router prompt from CPE" + dev_dict["ip"] + " CLI. please check")
        return "Redispatch not Success"
    time.sleep(2)
    return netconnect


def take_device_states(state = "before_upgrade"):
    global report, cpe_list, parsed_dict, cpe_logger, cpe_logger_dict
    for i, rows in cpe_list.iterrows():
        dev_dict = {
            "device_type": 'versa', "ip": cpe_list.ix[i, 'ip'], \
            "username": vd_dict['cpe_user'], "password": vd_dict['cpe_passwd'], \
            "port": '22'
        }
        # dev_dict = {
        #     "device_type": cpe_list.ix[i, 'type'], "ip": cpe_list.ix[i, 'ip'], \
        #     "username": cpe_list.ix[i, 'username'], "password": cpe_list.ix[i, 'password'], \
        #     "port": cpe_list.ix[i, 'port']
        # }
        cpe_name = cpe_list.ix[i, 'device_name_in_vd']
        cpe_logger = cpe_logger_dict[cpe_name]
        netconnect = do_cross_connection(vd_ssh_dict, dev_dict)
        if netconnect == "VD to CPE " + dev_dict["ip"] + "ssh Failed.":
                cpe_result = [cpe_name, "VD -> CPE " + dev_dict["ip"] + " SSH connection failed"]
                report.append(cpe_result)
                cpe_list = cpe_list.drop(index=i)
                cpe_logger.info(cpe_name + " : VD -> CPE " + dev_dict["ip"] + " SSH connection failed. please check IP & reachabilty from VD")
                continue
        if netconnect == "Redispatch not Success":
                cpe_result = [cpe_name, "CPE Redispatch failed"]
                report.append(cpe_result)
                cpe_list = cpe_list.drop(index=i)
                cpe_logger.info(cpe_name + " : CPE Redispatch Success")
                continue

        org = cpe_list.ix[i, 'org']
        pack_info = get_package_info(netconnect)
        if state == "before_upgrade":
            if pack_info['PACKAGE_NAME'] == cpe_list.ix[i, 'package_info']:
                cpe_result = [cpe_name, "device already running with same package"]
                report.append(cpe_result)
                cpe_list = cpe_list.drop(index=i)
                cpe_logger.info(cpe_name + " : device already running with same package")
                continue
            timestamp = str(datetime.now().strftime("%Y-%m-%d-%H:%M:%S")).replace(" ", "")
            snapshot_desc = "PRE-UPGRADE-" + timestamp
            snapshot_timestamp = take_snapshot(netconnect, snapshot_desc)
        cmd2 = 'show bgp neighbor org ' + org + ' brief | nomore'
        parse1 = parse_send_command(netconnect, cmd1, interface_template)
        parse2 = parse_send_command(netconnect, cmd2, bgp_nbr_template)
        parse3 = parse_send_command(netconnect, cmd3, route_template)
        parse4 = parse_send_command(netconnect, cmd4, show_config_template)
        parsed_dict[cpe_name + state] = {'packageinfo' : pack_info['PACKAGE_NAME'], 'interfacelist' : parse1, 'bgpnbrlist' : parse2, 'routelist' : parse3, 'configlist' : parse4}
        if state == "before_upgrade":
            cpe_parsed_data = [[cpe_name], [pack_info['PACKAGE_NAME']], [snapshot_timestamp], parse1, parse2, parse3, parse4]
        else:
            cpe_parsed_data = [[cpe_name], [pack_info['PACKAGE_NAME']], parse1, parse2, parse3, parse4]
        # cpe_logger.info(cpe_parsed_data)
        write_cpe_output(cpe_parsed_data, state)
        close_cross_connection(netconnect)
        close_connection(netconnect)


def parse_send_command(netconnect, cmd, parse_template):
    global cpe_logger
    cpe_logger.info("CMD>> : " + cmd)
    output = netconnect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    cpe_logger.info(output)
    time.sleep(1)
    template = open(parse_template)
    re_table = textfsm.TextFSM(template)
    fsm_results =  re_table.ParseText(output.encode("utf-8"))
    fsm_result_str = ""
    fsm_result_str+= "     ".join(re_table.header) + "\n"
    for row in fsm_results:
        fsm_result_str += "     ".join(row) + "\n"
    return fsm_result_str


def do_rest_upgrade():
    global report, cpe_list, cpe_logger
    task_list = []
    main_logger.info("CPE's LIST for Upgrade")
    for i, rows in cpe_list.iterrows():
        main_logger.info(cpe_list.ix[i, 'device_name_in_vd'])
    for i, rows in cpe_list.iterrows():
        body_params = {
            'PACKAGE_NAME': cpe_list.ix[i, 'package_name'],
            'DEVICE_NAME': cpe_list.ix[i, 'device_name_in_vd']
        }
        body = config_template(t1.body_temp, body_params)
        json_data = json.loads(body)
        task_list.append(rest_operation(vdurl, user, passwd, json_data))
        main_logger.info("TASK LISTS : ")
        main_logger.info(task_list)
    while task_list:
        for task_id in task_list:
            task_state = check_task_status(vdurl, user, passwd, task_id)
            if task_state == "100":
                task_list.remove(task_id)


def rest_operation(vd, user, passwd, json_data):
    global cpe_logger
    response = requests.post(vd + upgrade_dev_url,
                             auth=(user, passwd),
                             headers=headers2,
                             json=json_data,
                             verify=False)

    main_logger.info(response.text)
    print response.text
    data = response.json()
    taskid = str(data['output']['result']['task']['task-id'])
    return taskid


def check_task_status(vd, user, passwd, taskid):
    global cpe_logger, cpe_logger_dict
    # cpe_logger.info(taskid)
    # percent_completed = 0
    # while percent_completed < 100:
    response1 = requests.get(vd + task_url + taskid,
                             auth=(user, passwd),
                             headers=headers3,
                             verify=False)
    data1 = response1.json()
    main_logger.info(data1)
    percent_completed = data1['versa-tasks.task']['versa-tasks.percentage-completion']
    main_logger.info(percent_completed)
    main_logger.info("Sleeping for 5 seconds")
    time.sleep(5)
    # return data1['task']['task-status']
    return str(percent_completed)




def PreUpgradeActions():
    global report
    global cpe_list
    do_checks()
    take_device_states()


def UpgradeAction():
    main_logger.info("<>" * 50)
    main_logger.info("UPGRADE CPEs via REST ")
    main_logger.info("<>" * 50)
    do_rest_upgrade()

def PostUpgradeActions():
    global report
    global cpe_list
    do_checks(state="after_upgrade")
    take_device_states(state="after_upgrade")


def compare_states():
    global report, cpe_list, parsed_dict, cpe_logger, main_logger, cpe_logger_dict
    for i, rows in cpe_list.iterrows():
        cpe_name = cpe_list.ix[i, 'device_name_in_vd']
        beforeupgrade = parsed_dict[cpe_name + "before_upgrade"]
        afterupgrade = parsed_dict[cpe_name + "after_upgrade"]

        upgrade = check_parse(cpe_name, "package", cpe_list.ix[i, 'package_info'], afterupgrade['packageinfo'])
        if upgrade == "OK":
            upgrade = "Success - " + beforeupgrade['packageinfo'] + " to " + cpe_list.ix[i, 'package_info']
        else:
            upgrade = "Failed to upgrade - " + beforeupgrade['packageinfo'] + " to " + cpe_list.ix[i, 'package_info']
        interface_match = check_parse(cpe_name, " interface ", beforeupgrade['interfacelist'], afterupgrade['interfacelist'])
        bgp_nbr_match = check_parse(cpe_name, " bgp ", beforeupgrade['bgpnbrlist'], afterupgrade['bgpnbrlist'])
        route_match = check_parse(cpe_name, " route ", beforeupgrade['routelist'], afterupgrade['routelist'])
        config_match = check_parse(cpe_name, " running-config ", beforeupgrade['configlist'], afterupgrade['configlist'])
        cpe_result = [cpe_name, upgrade, interface_match, bgp_nbr_match, route_match, config_match]
        report.append(cpe_result)





def cpe_list_print():
    # print "BELOW ARE THE CPEs going for Upgrade:\n"
    main_logger.info("BELOW ARE THE CPEs going for Upgrade:")
    for i, rows in cpe_list.iterrows():
        # print cpe_list.ix[i, 'device_name_in_vd'] + "\n"
        main_logger.info(cpe_list.ix[i, 'device_name_in_vd'])
    time.sleep(1)
    if raw_input("shall we proceed for Upgrade. Please Enter YES or NO\n") != "YES":
        main_logger.info("You are not entered YES. Script exiting")
        exit()


def write_result(results):
    data_header = ['cpe', 'upgrade', 'interface', 'bgp_nbr_match', 'route_match', 'config_match']
    with open(logfile_dir + 'RESULT.csv', 'w') as file_writer:
        writer = csv.writer(file_writer)
        writer.writerow(data_header)
        for item in results:
            writer.writerow(item)
        for result1 in results:
            main_logger.info("==" * 50)
            for header, res in zip(data_header, result1):
                main_logger.info(header + ":" + res)
            main_logger.info("==" * 50)


def write_cpe_output(results, state):
    write_output_filename = logfile_dir + "/PARSED_DATA/" + str(results[0][0]) + "_outputs.txt"

    if not os.path.exists(os.path.dirname(write_output_filename)):
        try:
            os.makedirs(os.path.dirname(write_output_filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    if state == "before_upgrade":
        data_header = ['cpe', 'before_upgrade_package_info', 'snapshot taken', 'before_upgrade_interface', 'before_upgrade_bgp_nbr_match', 'before_upgrade_route_match', 'before_upgrade_config_match']
        try:
            os.remove(write_output_filename)
        except OSError:
            pass
    elif state == "after_upgrade":
        data_header = ['cpe', 'after_upgrade_package_info', 'after_upgrade_interface', 'after_upgrade_bgp_nbr_match', 'after_upgrade_route_match', 'after_upgrade_config_match']

    with open(write_output_filename, "a") as f:
        for i in range(len(data_header)):
            print >> f, data_header[i]
            print >> f, "===" * 50
            print >> f, results[i]
            # for idx, k in enumerate(j):
            #         print >> f, k
            print >> f, "===" * 50



def write_output(results):
    write_output_filename = fileDir + "/PARSED_DATA/" + str(results[0][0]) + "_outputs.txt"
    data_header = ['cpe', 'before_upgrade_package_info', 'after_upgrade_package_info', 'before_upgrade_interface', 'after_upgrade_interface', 'before_upgrade_bgp_nbr_match', 'after_upgrade_bgp_nbr_match', 'before_upgrade_route_match', 'after_upgrade_route_match', 'before_upgrade_config_match', 'after_upgrade_config_match']
    if not os.path.exists(os.path.dirname(write_output_filename)):
        try:
            os.makedirs(os.path.dirname(write_output_filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    with open(write_output_filename, "w") as f:
        for i, j in zip(data_header, results):
            print >> f, i
            print >> f, "===" * 50
            for idx, k in enumerate(j):
                    print >> f, k
            print >> f, "===" * 50



# def read_excel_sheet(filename, sheet):
#     pl = pd.read_excel(filename, sheet)
#     return pl


def config_template(text, params1):
    template = Template(text)
    txt = template.safe_substitute(params1)
    return txt


def make_connection(a_device):
    global main_logger
    try:
        net_connect = ConnectHandler(**a_device)
        output = net_connect.read_channel()
        main_logger.info(output)
    except ValueError as Va:
        main_logger.info(Va)
        main_logger.info("Not able to enter Versa Director CLI. please Check")
        exit()
    net_connect.enable()
    time.sleep(5)
    main_logger.info("{}: {}".format(net_connect.device_type, net_connect.find_prompt()))
    # print str(net_connect) + " connection opened"
    main_logger.info(str(net_connect) + " connection opened")
    return net_connect


def close_cross_connection(nc):
    time.sleep(1)
    main_logger.info(nc.write_channel("exit\n"))
    time.sleep(1)
    main_logger.info(nc.write_channel("exit\n"))
    time.sleep(1)
    redispatch(nc, device_type='versa')
    main_logger.info(nc.find_prompt())



def request_ping(net_connect, cpe):
    cmd = "request devices device " + cpe + " ping"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" 0% packet loss" in output)


def request_connect(net_connect, cpe):
    cmd = "request devices device " + cpe + " connect"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" Connected to" in output)


def request_live_status(net_connect, cpe):
    cmd = "request devices device " + cpe + " check-sync"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str("result in-sync" in output)


def request_sync_from_cpe(net_connect, cpe):
    cmd = "request devices device " + cpe + " sync-from"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" result true" in output)


def check_device_status(nc, device_name, device_ip, state):
    # if ping(nc, device_ip) != "True":
    #     return "VD --> CPE " + device_ip + " ping failed."
    if request_ping(nc, device_name) == "True":
        if request_connect(nc, device_name) == "True":
            if request_live_status(nc, device_name) == "True":
                return "PASS"
            else:
                # if request_sync_from_cpe(nc, device_name):
                #     if request_live_status(nc, device_name) == "True":
                #         return "PASS"
                #     else:
                #         return "CPE out-of sync."
                # else:
                #     return "VD --> CPE Request sync failed."
                return "CPE out-of sync."
        else:
            return "VD --> CPE Request connect failed."
    else:
        return "VD --> CPE Request ping failed."


def remove_last_line_from_string(s):
    return s[:s.rfind('\n')]


def check_parse(cpe, outputof, before_upgrade , after_upgrade):
    global cpe_logger, cpe_logger_dict
    check_result = "OK"
    deleted = ""
    added = ""
    not_matched = ""
    if outputof == " running-config ":
        if before_upgrade != after_upgrade:
            for j in before_upgrade.split("\n"):
                if j not in after_upgrade:
                    deleted += j + "\n"
                    check_result = "NOK"
            for i in after_upgrade.split("\n"):
                if i not in before_upgrade:
                    added += i + "\n"
                    check_result = "NOK"
        if deleted != "":
            cpe_logger.info("==" * 50)
            cpe_logger.info("After Upgrade deleted Lines in config")
            cpe_logger.info("==" * 50)
            cpe_logger.info("\n" + deleted)
            cpe_logger.info("==" * 50)

        if added != "":
            cpe_logger.info("==" * 50)
            cpe_logger.info("After Upgrade added Lines in config")
            cpe_logger.info("==" * 50)
            cpe_logger.info("\n" + added)
            cpe_logger.info("==" * 50)
    elif outputof == "package":
        if before_upgrade != after_upgrade:
            cpe_logger.info("==" * 50)
            cpe_logger.info("Cpe current package after upgrade: " + after_upgrade)
            cpe_logger.info("Cpe not upgrade to " + before_upgrade)
            cpe_logger.info("==" * 50)
            check_result = "NOK"
    else:
        if before_upgrade != after_upgrade:
            for j in before_upgrade.split("\n"):
                if j not in after_upgrade:
                    not_matched += j + "\n"
                    check_result = "NOK"
            if not_matched != "":
                cpe_logger.info("==" * 50)
                cpe_logger.info(outputof + " not matched after upgrade")
                cpe_logger.info("==" * 50)
                cpe_logger.info("\n" + not_matched)
                cpe_logger.info("==" * 50)
    # cpe_logger.info("<>" * 50)
    # cpe_logger.info("Post Upgrade Check Done.")
    # cpe_logger.info("<>" * 50)
    return check_result



def close_connection(net_connect):
    net_connect.disconnect()
    main_logger.info(str(net_connect) + " connection closed")


def ping(net_connect, dest_ip, **kwargs):
    cmd = "ping " + str(dest_ip)
    paramlist = ['count', 'df_bit', 'interface', 'packet_size', 'rapid',
                 'record-route', 'routing_instance', 'source']
    for element in paramlist:
        if element in kwargs.keys():
            cmd =  cmd + " " + element.replace('_', '-') + " "+ str(kwargs[element])
    try:
        main_logger.info("CMD>> : " + cmd)
        output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    except IOError as Io:
        cpe_logger.info(Io)
        net_connect.send_command_expect("\x03", strip_prompt=False, strip_command=False)
        cpe_logger.info("Ping failed")
        return "Ping failed"
    main_logger.info(output)
    return str(" 0% packet loss" in output)


def get_snapshot(net_connect, desc):
    global cpe_logger
    cmd = "show system snapshots | tab | match " + desc
    cpe_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    cpe_logger.info(output)
    output1 = output.split("\n")
    return str(output1[1].split()[0])


def take_snapshot(net_connect, desc):
    global cpe_logger
    cmd = "request system create-snapshot description " + str(desc) + " no-confirm"
    cpe_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    cpe_logger.info(output)
    return get_snapshot(net_connect, desc)


def rollback_snapshot(net_connect, snapshot_timestamp):
    global cpe_logger
    cmd = "request system rollback to " + snapshot_timestamp + " no-confirm"
    cpe_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    print output


def get_interface_status(net_connect, intf_name):
    """Get interface status. Return LAN VRF name and subnet"""
    cmd = 'show interfaces brief ' + str(intf_name) + ' | tab'
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    output_string = str(output)
    print output_string
    output_list = output_string.split("\n")
    intf_dict = {}
    keys = output_list[0].split()
    values = output_list[2].split()
    for i in xrange(len(keys)):
        intf_dict[keys[i]] = values[i]
    return intf_dict


def get_package_info(net_connect):
    global cpe_logger
    cmd = 'show system package-info | tab'
    cpe_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    cpe_logger.info(output)
    output_string = str(output)
    print output_string
    output_list = output_string.split("\n")
    intf_dict = {}
    values = output_list[4].split()
    intf_dict['PACKAGE_ID'] = values[0]
    intf_dict['MAJOR'] = values[1]
    intf_dict['MINOR'] = values[2]
    intf_dict['DATE'] = values[3]
    intf_dict['PACKAGE_NAME'] = values[4]
    intf_dict['REL_TYPE'] = values[5]
    intf_dict['BUILD_TYPE'] = values[6]
    intf_dict['BRANCH'] = values[7]
    return intf_dict

def convert_string_dict(output_str):
    output_string = str(output_str)
    dict1 = {}
    for i in output_string.split("\n"):
        k = i.split()
        dict1[k[0]] = k[1:]
    return dict1


