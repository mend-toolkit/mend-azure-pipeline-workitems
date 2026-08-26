import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _version import __tool_name__, __version__, __description__
from core import run_sync, startup, load_wi_json, apply_custom_fields, AGENT_INFO, \
    check_patterns, sync_had_fatal_error, error_count

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
    if conf.routing.lower() == "true":
        # No startup probe: MEND_AZUREPROJECT is not a destination under routing and is no
        # longer required, so there may be no project here to probe. run_sync_routed reads the
        # work item type from each destination instead, and skips a destination that lacks it.
        wi_type, wi_fields = conf.azure_type, []
    else:
        wi_type, wi_fields = load_wi_json()
        if not wi_fields:
            logger.error(f"The Workitem type {conf.azure_type} was not found")
            exit(-1)
    conf.utc_delta = int((datetime.datetime.utcnow()-datetime.datetime.now()).total_seconds()/3600)  # in hours
    logger.info("Sync process started")
    # Under routing this list is empty and each destination's own field list is filled in by
    # run_sync_routed, which calls apply_custom_fields itself.
    wi_fields = apply_custom_fields(wi_fields)

    now = datetime.datetime.now() + datetime.timedelta(hours=conf.utc_delta)
    todate = now.strftime("%Y-%m-%d %H:%M:%S")
    # No write probe and no exit: no Azure project property is read or written any more.
    # run_sync now drives everything from Mend 3.0 and reconciles (closes/reopens) each project
    # inline, right after creating that project's work items and from the same read at the same
    # severity floor -- so there is no separate reconcile_after_sync() pass here to run at a
    # different threshold. st_date is unused on the 3.0 path (no windows, no watermarks).
    logger.info(run_sync("", todate, wi_fields, wi_type))
    if sync_had_fatal_error():
        logger.error("The sync did not complete. Mend 3.0 reports each project's full current "
                     "state, so the projects that failed are simply read again in full on the "
                     "next run.")
        logger.error("Sync process FAILED. Please look at the log.")
        exit(1)
    errors = error_count()
    if errors == 0:
        logger.info("Sync process completed successfully")
    else:
        logger.info(f"Sync process finished with {errors} errors. Please, looks at the log.")


if __name__ == '__main__':
    main()
