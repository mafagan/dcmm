
cfg_items = {
    'session_size': 'Greater than 100',
    'cache_size': 'Greater than 100000',
    'log': '',
    'syslog': '',
    'read_threshold': 'Greater than 0',
    'db_cache_size': 'Greater than 0 and less than value session_size',
    'db_cache_msg_size': 'Greater than 0 and less than value session_size',
    'rate': 'Greater than 0'
}

info = {
    'passwd_str': 'Basic ZGNtbTpkY21t'
}

dcmm_conf_file = '/etc/dcmm.conf'

log_items = [
    'trace',
    'debug',
    'info',
    'warn',
    'error'
]

select_items = [
    'log',
    'sys_log'
]

status_code = {
    200: "Status: 200 OK\r\n",
    401: "Status: 401 Unauthorized\r\n"
}
