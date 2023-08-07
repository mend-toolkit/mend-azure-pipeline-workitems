import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _version import __tool_name__, __version__, __description__
from core import run_sync, update_wi_in_thread, startup, get_lastrun, set_lastrun, load_wi_json, AGENT_INFO, \
    check_patterns, global_errors

logger = logging.getLogger(__tool_name__)
logging.getLogger('urllib3').setLevel(logging.INFO)
conf = None
wi_fields = None
wi_type = None


def main():
    global conf
    global wi_fields, wi_type

    hdr_title = f'Mend Azure Work Items Sync {AGENT_INFO["agentVersion"]}'
    hdr = f'\n{len(hdr_title) * "="}\n{hdr_title}\n{len(hdr_title) * "="}'
    logger.info(hdr)
    conf = startup() if not conf else conf
    conf.update_properties()
    chp_ = check_patterns()
    if chp_:
        logger.error("Missing or malformed configuration parameters:")
        [logger.error(el_) for el_ in chp_]
        exit(-1)
    # logger.debug(conf)  # TEMP
    wi_type, wi_fields = load_wi_json()
    if not wi_fields:
        logger.error(f"The Workitem type {conf.azure_type} was not found")
        exit(-1)
    conf.utc_delta = int((datetime.datetime.utcnow()-datetime.datetime.now()).total_seconds()/3600)  # in hours
    last_run = get_lastrun(conf.utc_delta, conf.reset)
    if set_lastrun(lastrun=last_run) == 2:  # Serious error
        exit(-1)
    logger.info("Sync process started")
    if conf.reset.lower() != "true":
        logger.warning("MEND_RESET parameter set to FALSE, only creating work items since last ran scan")
    if conf.azure_custom:
        custom_flds = conf.azure_custom.split(";")
        for c_fld_ in custom_flds:
            field_name_from_param = c_fld_.split("::")
            fld_ref = f"Custom.{field_name_from_param[0]}"
            for w_field_ in wi_fields:
                if fld_ref == w_field_["referenceName"] or field_name_from_param[0] == w_field_["name"]:
                    w_field_["defaultValue"] = field_name_from_param[1]
                    break

    now = datetime.datetime.now() + datetime.timedelta(hours=conf.utc_delta)
    todate = now.strftime("%Y-%m-%d %H:%M:%S")
    time_sync = (now-datetime.datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")).total_seconds()/3600  # in hours
    time_sync = time_sync if time_sync > 1 else 1  # Minimal sync time period is 1 hour
    logger.info(run_sync((now - datetime.timedelta(hours=time_sync)).strftime("%Y-%m-%d %H:%M:%S"),
                     todate, wi_fields, wi_type))
    logger.info(update_wi_in_thread())
    now = datetime.datetime.now() + datetime.timedelta(hours=conf.utc_delta)
    set_lastrun(now.strftime("%Y-%m-%d %H:%M:%S"))
    if global_errors == 0:
        logger.info("Sync process completed successfully")
    else:
        logger.info(f"Sync process finished with {global_errors} errors. Please, looks at the log.")


if __name__ == '__main__':
    main()
