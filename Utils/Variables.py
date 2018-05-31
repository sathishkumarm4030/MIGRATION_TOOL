import os
import pandas as pd
import getpass

cpe_list = ""

if __name__ == "__main__":
    fileDir = os.path.dirname(os.path.dirname(os.path.realpath('__file__')))
else:
    fileDir = os.path.dirname(os.path.realpath('__file__'))

cpe_details = os.path.join(fileDir, 'upgrade_device_list.csv')


interface_template = os.path.join(fileDir, 'Utils/TEXTFSM/versa_interface_template')
bgp_nbr_template = os.path.join(fileDir, 'Utils/TEXTFSM/versa_bgp_neighbor_org_template')
route_template = os.path.join(fileDir, 'Utils/TEXTFSM/versa_route_template')
show_config_template = os.path.join(fileDir, 'Utils/TEXTFSM/versa_show_config_template')


def read_excel_sheet(filename, sheet):
    pl = pd.read_excel(filename, sheet)
    return pl

def read_csv_file(filename, day, batch):
    csv_data_read = pd.read_csv(filename)
    pl = csv_data_read.loc[csv_data_read['day'] == int(day)]
    filtered_cpes = pl.loc[pl['batch'] == int(batch)]
    return filtered_cpes


def get_vd_details():
    global cpe_list
    ip = raw_input("Enter Versa Director IP address:\n")
    print "Versa director IP:" + ip
    ldap_user = raw_input("Enter LDAP Username for making SSH connection to VD:\n")
    print "Versa director Username:" + ldap_user
    ldap_passwd = getpass.getpass("Enter LDAP Password:\n")
    user = raw_input("Enter Username for making REST actions to Versa Director :\n")
    print "Versa director Username:" + user
    passwd = getpass.getpass("Enter REST Password:\n")
    cpe_user = raw_input("Enter Versa CPE Username:\n")
    print "Versa director Username:" + cpe_user
    cpe_passwd = getpass.getpass("Enter Versa CPE Password:\n")
    day = int(raw_input("Enter DAY:\n"))
    batch = int(raw_input("Enter BATCH:\n"))
    # ip = '10.91.127.194'
    # user = 'MSK'
    # passwd = 'Versa@123'
    # day = '2'
    cpe_list = read_csv_file(cpe_details, day, batch)
    while len(cpe_list) == 0:
        print "No Cpe matched for Day and batch entered."
        day = int(raw_input("Please reenter correct DAY:\n"))
        batch = int(raw_input("Please reenter correct Batch:\n"))
        cpe_list = read_csv_file(cpe_details, day, batch)
    return {'ip' : ip, 'user': user, 'passwd': passwd, 'ldap_user' : ldap_user,
                  'ldap_passwd' : ldap_passwd, 'cpe_user' : cpe_user, 'cpe_passwd' : cpe_passwd}



#Variables
task_url_old_vd = "/api/operational/tasks/task/"
task_url = "/vnms/tasks/task/"
upgrade_dev_url = "/api/config/nms/actions/packages/upgrade"
headers = {'Accept': 'application/vnd.yang.data+json'}
headers2 = {'Accept': 'application/vnd.yang.data+json', 'Content-Type': 'application/vnd.yang.data+json'}
headers3 = {'Accept': 'application/json', 'Content-Type': 'application/json'}

vd_dict = get_vd_details()
vdurl = 'https://' + vd_dict['ip'] + ':9182'
user = vd_dict['user']
passwd = vd_dict['passwd']
# day = vd_dict['day']
vd_ssh_dict = {
    'device_type': 'versa',
    'ip': vd_dict['ip'],
    'username': vd_dict['ldap_user'],
    'password': vd_dict['ldap_passwd'],
    'port': 22,
}

cmd1 = 'show interfaces brief | tab | nomore'
cmd2 = 'show bgp neighbor brief | nomore'
cmd3 = 'show route | nomore'
cmd4 = 'show configuration | display set | nomore'

