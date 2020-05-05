import logging
import os
import sys

try:
    import colorlog

    HAVE_COLORLOG = True
except ImportError:
    HAVE_COLORLOG = False


class LessThanFilter(logging.Filter):
    def __init__(self, exclusive_maximum, name=""):
        super(LessThanFilter, self).__init__(name)
        self.max_level = exclusive_maximum

    def filter(self, record):
        return 1 if record.levelno < self.max_level else 0


def setup_logger():
    log = logging.getLogger()
    log.setLevel(logging.NOTSET)
    format_str = '%(asctime)s - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if HAVE_COLORLOG and os.isatty(2):
        formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
            "%(white)s%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            reset=True,
            log_colors={
                'DEBUG': 'reset',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red',
            })
    else:
        formatter = logging.Formatter(format_str, date_format)
    logging_handler_out = logging.StreamHandler(sys.stdout)
    logging_handler_out.setLevel(logging.DEBUG)
    logging_handler_out.addFilter(LessThanFilter(logging.WARNING))
    logging_handler_out.setFormatter(formatter)
    log.addHandler(logging_handler_out)

    logging_handler_err = logging.StreamHandler(sys.stderr)
    logging_handler_err.setLevel(logging.WARNING)
    logging_handler_err.setFormatter(formatter)
    log.addHandler(logging_handler_err)

    return logging.getLogger(__name__)
