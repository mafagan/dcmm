
import macro

html_header_content_type = 'Content-type:text/html\r\n\r\n'

html_first_half = '<!DOCTYPE html>\
<html lang="en">\
    <head>\
        <meta charset="utf-8">\
        <title>Sign in &middot; Twitter Bootstrap</title>\
        <meta name="viewport" content="width=device-width, initial-scale=1.0">\
        <meta name="description" content="">\
        <meta name="author" content="">\
\
        <!-- Le styles -->\
        <link href="../stylesheet/bootstrap.css" rel="stylesheet">\
        <style type="text/css">\
            body {\
                padding-top: 40px;\
                padding-bottom: 40px;\
                background-color: #f5f5f5;\
            }\
\
            .form-signin {\
                max-width: 450px;\
                padding: 19px 29px 29px;\
                margin: 0 auto 20px;\
                background-color: #fff;\
                border: 1px solid #e5e5e5;\
                -webkit-border-radius: 5px;\
                -moz-border-radius: 5px;\
                border-radius: 5px;\
                -webkit-box-shadow: 0 1px 2px rgba(0,0,0,.05);\
                -moz-box-shadow: 0 1px 2px rgba(0,0,0,.05);\
                box-shadow: 0 1px 2px rgba(0,0,0,.05);\
            }\
            .form-signin .form-signin-heading,\
            .form-signin .checkbox {\
                margin-bottom: 10px;\
            }\
            .input-block-level{\
                font-size: 16px;\
                height: auto;\
                margin-bottom: 15px;\
                padding: 7px 9px;\
            }\
\
        </style>\
\
        <script type="text/javascript">\
            function checkSubmit(){\
\
                var numReg = "0|([1-9][0-9]*)";\
                if(config.session.value.match(numReg) == null){\
                    alert("Session value must be number!");\
                    return false;\
                }else if(parseInt(config.session.value) < 100){\
                    alert("Session value must be grater or equal 100!");\
                    return false;\
                }\
\
                if(config.cache.value.match(numReg) == null){\
                    alert("Cache value must be number!");\
                    return false;\
                }else if(parseInt(config.cache.value) < 10000){\
                    alert("Cache value must be grater or equal 10000!");\
                    return false;\
                }\
\
                if(config.read_threshold.value.match(numReg) == null){\
                    alert("Read_threshold value must be number!");\
                    return false;\
                }else if(parseInt(config.read_threshold.value) <= 0){\
                    alert("Read_threshold value must be grater than zero!");\
                    return false;\
                }else if(parseInt(config.read_threshold.value) > (parseInt(conf\
ig.cache.value))){\
                    alert("Read_threshold value must be less \
    than cache value!");\
                    return false;\
                }\
\
                if(config.db_cache_size.value.match(numReg) == null){\
                    alert("Db_cache_size value must be number!");\
                    return false;\
                }else if(parseInt(config.db_cache_size.value) < 0){\
                    alert("Db_cache_size value must be grater than zero!");\
                    return false;\
                }\
\
                if(config.db_cache_msg_size.value.match(numReg) == null){\
                    alert("Db_cache_msg_size value must be number!");\
                    return false;\
                }else if(parseInt(config.db_cache_msg_size.value) <= 0){\
                    alert("Db_cache_msg_size value must be grater than zero!");\
                    return false;\
                }else if(parseInt(config.db_cache_msg_size.value) > \
    (parseInt(config.cache.value))){\
                    alert("Db_cache_msg_size value must be less than cache \
    value!");\
                    return false;\
                }\
\
\
                if(config.rate.value.match(numReg) == null){\
                    alert("Rate value must be number!");\
                    return false;\
                }else if(parseInt(config.rate.value) <= 0){\
                    alert("Rate value must be grater than zero!");\
                    return false;\
                }\
            }\
        </script>\
        <!-- HTML5 shim, for IE6-8 support of HTML5 elements -->\
        <!--[if lt IE 9]>\
        <script src="../assets/js/html5shiv.js"></script>\
        <![endif]-->\
\
        <!-- Fav and touch icons -->\
    </head>\
        <body>\
\
            <form name="config" class="form-signin" action="/cgi/config.py" \
    method="POST" onsubmit="return checkSubmit()">\
                <table><tbody>\
\
                        <caption class="form-signin-heading">\
    DCMM CONFIG</caption>\
 '

html_second_half = '</tbody></table> \
                        <div style="text-align: center; margin: auto">\
    <button class="btn btn-large btn-primary" type="submit">Save</button></div>\
            </form>\
        </div> <!-- /container -->\
    </body>\
</html>\
'

html_input_before_label = '<tr>\
    <td><label>\
'
html_input_after_label = '</label></td>\
    <td>&nbsp&nbsp</td>\
    <td><input type="text" name="\
'

html_input_value_attri = '" value="'

html_input_class_attri = '" class="input-block-level" placeholder="'

html_input_after_ph = '"></td></tr>'


html_select_before_label = '<tr><td><label>'

html_select_before_name = '</label></td><td>&nbsp&nbsp</td><td><select name="'

html_select_before_option = '" class="input-block-level">'


html_select_option_first = '<option '

html_select_option_second = '>'

html_select_option_third = '</option>'

html_select_option_selected = 'selected="selected"'

html_select_after_option = ' </select></td></tr>'


def get_option_block(value):
    res = ''
    for log_item in macro.log_items:
        res = res + html_select_option_first

        if value == log_item:
            res = res + html_select_option_selected

        res = res + html_select_option_second + log_item +\
            html_select_option_third
    return res


def get_input_block(key, value, placeholder):
    return html_input_before_label + key + html_input_after_label + key + \
        html_input_value_attri + value + html_input_class_attri + placeholder +\
        html_input_after_ph


def get_select_block(key, value):
    res = html_select_before_label + key + html_select_before_name + key + \
        html_select_before_option + get_option_block(value) + \
        html_select_before_option

    return res


def get_html_header(status):
    str = macro.status_code[status] + html_header_content_type
    return str


def get_html_body(in_dict):
    res = html_first_half

    for key, value in in_dict.items():
        if key == 'log' or key == 'syslog':
            res = res + get_select_block(key, value)
        else:
            res = res + get_input_block(key, value, macro.cfg_items[key])

    res = res + html_second_half
    return res


def get_html(in_dict, status):
    str = get_html_header(status) + get_html_body(in_dict)
    return str
