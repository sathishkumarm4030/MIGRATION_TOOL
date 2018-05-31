#!/usr/bin/env python

"""
This Tool is designed for upgrading Versa CPE.
"""

__author__ = "Sathishkumar murugesan"
__copyright__ = "Copyright(c) 2018 Colt Technologies india pvt ltd."
__credits__ = ["Danny Pinto"]
__license__ = "GPL"
__version__ = "1.0.1"
__maintainer__ = "Sathishkumar Murugesan"
__email__ = "Sathishkumar.Murugesan@colt.net"
__status__ = "Developed"


from Utils.Commands import *


def cpe_upgrade():
    cpe_list_print()
    PreUpgradeActions()
    UpgradeAction()
    PostUpgradeActions()
    compare_states()
    write_result(report)


def main():
    main_logger.info("SCRIPT Started")
    # print cpe_list
    start_time = datetime.now()
    cpe_upgrade()
    main_logger.info("SCRIPT Completed.")
    main_logger.info("Result Stored in " + logfile_dir + "/RESULT.csv")
    main_logger.info("LOG FILES Path: " + logfile_dir)
    main_logger.info("Time elapsed: {}\n".format(datetime.now() - start_time))


if __name__ == "__main__":
    main()
