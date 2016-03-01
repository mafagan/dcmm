#include "logging.h"
#include "config_manager.h"

extern config_t config;

static log4c_rc_t __log4c_rc = { { 0, 0, 0, 0 } };

log4c_rc_t* const log4c_rc = &__log4c_rc;

/**********************************************************************
 * Formatted to put [category] out at the front of the message
 *********************************************************************/
static const char* cat_format(
        const log4c_layout_t*       a_layout,
        const log4c_logging_event_t*a_event)
{
    static char buffer[4096];

    /*
     * For this formatter we put the category up front in the log message
     */
    sprintf(buffer, "[%s][LINE:%d][FILE:%s] %s", a_event->evt_category,
            a_event->evt_loc->loc_line, a_event->evt_loc->loc_file, a_event->evt_msg);

    return buffer;
}

const log4c_layout_type_t log4c_layout_type_cat  = {
    "default_layout_cat",
    cat_format,
};


static const char* none_format(
        const log4c_layout_t*       a_layout,
        const log4c_logging_event_t*a_event)
{
    static char buffer[4096];
    return buffer;
}

const log4c_layout_type_t log4c_layout_type_none  = {
    "default_layout_none",
    none_format,
};

static int file_append(log4c_appender_t* this,
        const log4c_logging_event_t* a_event)
{
    FILE* fp = log4c_appender_get_udata(this);
    return fprintf(fp, "%s\n", a_event->evt_rendered_msg);
}

/*******************************************************************************/
static int etf_open(log4c_appender_t* this)
{
    FILE* fp = log4c_appender_get_udata(this);

    if (fp)
        return 0;

    if ( (fp = fopen(log4c_appender_get_name(this), "a+")) == NULL) {
        printf("%s\n", log4c_appender_get_name(this));
        fp = stderr;
    }

    /* unbuffered mode */
    setbuf(fp, NULL);

    log4c_appender_set_udata(this, fp);
    return 0;
}


/*******************************************************************************/
static int etf_close(log4c_appender_t* this)
{
    FILE* fp = log4c_appender_get_udata(this);

    return (fp ? fclose(fp) : 0);
}

const log4c_appender_type_t log4c_appender_type_file = {
    "default_appender_file",
    etf_open,
    file_append,
    etf_close,
};

/*******************************************************************************/
/*
 * The log4c stderr adds a "[stderr] " in front of the message
 * it is logging.  this one doesn't, and  leaves the formatting
 * descisions up to the formatter
 */
static int stderr_append(log4c_appender_t* this,
        const log4c_logging_event_t* a_event)
{
    return fprintf(stderr, "%s\n", a_event->evt_rendered_msg);
}
static int stderr_open(log4c_appender_t* this)
{
    /* fprintf (stderr,"running default_appender_stderr appender open command now\n"); */
    return 0;
}

/**********************************************************************
 *
 * Formatted to look for extended user location info
 *
 **********************************************************************/
static const char* userloc_format(
        const log4c_layout_t*       a_layout,
        const log4c_logging_event_t*a_event)
{
    static char buffer[4096];
    user_locinfo_t* uloc = NULL;

    sd_debug("Formatter default_formatter_userloc checking location info for userdata %X",a_event->evt_loc->loc_data);
    if (a_event->evt_loc->loc_data != NULL)
    {
        sd_debug("Formatter default_formater_userloc getting a valid user location info pointer");
        uloc = (user_locinfo_t*) a_event->evt_loc->loc_data;
        sprintf(buffer, "[%s][HOST:%s][PID:%i][FILE:%s][LINE:%i][MSG:%s]",
                a_event->evt_category,
                uloc->hostname, uloc->pid, a_event->evt_loc->loc_file,
                a_event->evt_loc->loc_line,a_event->evt_msg);

    }
    else
    {
        sprintf(buffer, "[%s]::[FILE:%s][LINE:%i][MSG::%s]",
                a_event->evt_category,
                a_event->evt_loc->loc_file,
                a_event->evt_loc->loc_line,a_event->evt_msg);
    }
    return buffer;
}

const log4c_layout_type_t log4c_layout_type_userloc  = {
    "default_layout_userloc",
    userloc_format,
};

/*****************************/
/*
 * Customized appender
 *
 ******************************/
const log4c_appender_type_t log4c_appender_type_stderr = {
    "default_appender_stderr",
    stderr_open,
    stderr_append,
    NULL,
};

static const log4c_appender_type_t * const appender_types[] = {
    &log4c_appender_type_file,
    &log4c_appender_type_stderr,
    &log4c_appender_type_stream,
    &log4c_appender_type_stream2,
    &log4c_appender_type_mmap,
    &log4c_appender_type_syslog,
    &log4c_appender_type_rollingfile,
};
int nappender_types =
(int)(sizeof(appender_types) / sizeof(appender_types[0]));

int init_custom_appenders()
{

    int rc = 0; int i = 0;

    for (i = 0; i < nappender_types; i++)
        log4c_appender_type_set(appender_types[i]);

    return(rc);
}

/*****************************/
/*
 * Customized formatter
 *
 ******************************/
static const log4c_layout_type_t * const layout_types[] = {
    &log4c_layout_type_none,
    &log4c_layout_type_cat,
    &log4c_layout_type_userloc,
    &log4c_layout_type_basic,
    &log4c_layout_type_dated,
    &log4c_layout_type_dated_local,
    &log4c_layout_type_basic_r,
    &log4c_layout_type_dated_r,
    &log4c_layout_type_dated_local_r,
};
static int nlayout_types =
(int)(sizeof(layout_types) / sizeof(layout_types[0]));


int init_custom_layouts()
{

    int rc = 0; int i = 0;

    for (i = 0; i < nlayout_types; i++)
        log4c_layout_type_set(layout_types[i]);

    return(rc);

}

static const log4c_rollingpolicy_type_t * const rollingpolicy_types[] = {
    &log4c_rollingpolicy_type_sizewin
};
static size_t nrollingpolicy_types =
sizeof(rollingpolicy_types) / sizeof(rollingpolicy_types[0]);

int init_custom_rollingpolicy()
{

    int rc = 0; int i = 0;

    for (i = 0; i < nrollingpolicy_types; i++)
        log4c_rollingpolicy_type_set(rollingpolicy_types[i]);

    return(rc);

}

/*****************************/
/*
 * configuration load
 *
 ******************************/
extern int set_configuration
(
        int nocleanup,
        int bufsize,
        int debug,
        int reread,
        log4c_rc_t * this) {
    this->config.nocleanup = nocleanup;
    this->config.bufsize = bufsize;
    this->config.debug = debug;
    this->config.reread = reread;

    return 0;
}

int configuration_load(log4c_rc_t* this)
{
    log4c_category_t *cat = NULL;
    log4c_category_t *cat_syslog = NULL;
    log4c_rollingpolicy_t *rollingpolicyp = NULL;
    rollingfile_udata_t *rfup = NULL;
    rollingpolicy_sizewin_udata_t *sizewin_udatap = NULL;
    log4c_appender_t *app = NULL;
    log4c_appender_t *app_syslog = NULL;
    log4c_layout_t *layout = NULL;

    const char *logdir = ".";
    const char *logprefix = "dcmm.log";
    long a_maxsize = 1024 * 20;
    int maxnum = 10;

    cat = log4c_category_get("dcmm_log");
    cat_syslog = log4c_category_get("dcmm_syslog");
    rollingpolicyp = log4c_rollingpolicy_get("dcmm_rpolicy");
    app = log4c_appender_get("dcmm_rolling");
    app_syslog = log4c_appender_get("dcmm_calling_syslog");
    layout = log4c_layout_get("dcmm_dated");

    log4c_layout_set_type(layout, &log4c_layout_type_dated);
    log4c_appender_set_type(app, &log4c_appender_type_rollingfile);
    log4c_appender_set_type(app_syslog, &log4c_appender_type_syslog);
    log4c_appender_set_layout(app, layout);
    log4c_appender_set_layout(app_syslog, layout);
    /* TRACE DEBUG INFO WARN ERROR */
    log4c_category_set_priority(cat, log4c_priority_to_int(config.log));
    log4c_category_set_appender(cat, app);
    log4c_category_set_priority(cat_syslog, log4c_priority_to_int(config.syslog));
    log4c_category_set_appender(cat_syslog, app_syslog);

    rfup = rollingfile_make_udata();
    rollingfile_udata_set_logdir(rfup, logdir);
    rollingfile_udata_set_files_prefix(rfup, logprefix);
    rollingfile_udata_set_policy(rfup, rollingpolicyp);
    log4c_appender_set_udata(app, rfup);

    log4c_rollingpolicy_set_type(rollingpolicyp,
            log4c_rollingpolicy_type_get("sizewin"));
    sizewin_udatap = sizewin_make_udata();
    log4c_rollingpolicy_set_udata(rollingpolicyp, sizewin_udatap);
    sizewin_udata_set_file_maxsize(sizewin_udatap, a_maxsize);
    sizewin_udata_set_max_num_files(sizewin_udatap, maxnum);
    log4c_rollingpolicy_init(rollingpolicyp, rfup);

    return 0;
}

/*****************************/
/*
 * API
 *
 ******************************/

int log_init()
{
    /*Initialize default types: layouts, appenders, rollingpolicies */
    init_custom_layouts();
    init_custom_appenders();
    init_custom_rollingpolicy();
    set_configuration(0, 0, 0, 0, log4c_rc);
    configuration_load(log4c_rc);

    /*load configuration file */

}


int log_destroy()
{
    if (log4c_category_factory) {
        sd_factory_delete(log4c_category_factory);
        log4c_category_factory = NULL;
    }

    if (log4c_appender_factory) {
        sd_factory_delete(log4c_appender_factory);
        log4c_appender_factory = NULL;
    }
    log4c_appender_types_free();

    if (log4c_layout_factory) {
        sd_factory_delete(log4c_layout_factory);
        log4c_layout_factory = NULL;
    }
    log4c_layout_types_free();

    if (log4c_rollingpolicy_factory) {
        sd_factory_delete(log4c_rollingpolicy_factory);
        log4c_rollingpolicy_factory = NULL;
    }
    log4c_rollingpolicy_types_free();

    return 0;
}

