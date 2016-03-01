#!/usr/bin/python
import cgi
import macro
import config_view


def data_process():
    form = cgi.FieldStorage()

    conf_data = {}

    for key in macro.cfg_items:
        conf_data[key] = form.getvalue(key)

    f = open(macro.dcmm_conf_file, 'w')
    for key in conf_data:
        str = key + ' ' + conf_data[key] + '\n'
        f.writelines(str)
    f.close()


def config_handle():
    data_process()
    print config_view.get_html()

config_handle()
