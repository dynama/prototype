#!/usr/bin/env python

# Based on: http://www.tuxradar.com/content/code-project-build-ncurses-ui-python

__author__ =  'Erik Hunstad'
__version__=  '2.1'

from os import system
import curses
from main_analysis import main_analysis
import time, Queue, threading


"""
This module is the main module for the program. It runs the curses UI and calles relevent sub-modules.
"""


class live_update(threading.Thread):
    def __init__(self, screen, printQueue, startingLine):
        self.startingLine = startingLine
        self.printQueue = printQueue
        self.screen = screen
        self.stopUpdating = threading.Event()
        super(live_update, self).__init__()

    def run(self):
        printline = self.startingLine
        while not self.stopUpdating.isSet():
            while not self.printQueue.empty():
                if printline == self.startingLine:
                    self.screen.move(self.startingLine, 4)
                    self.screen.refresh()
                    self.screen.clrtobot()
                    self.screen.border(0)
                    self.screen.refresh()
                stringToPrint = self.printQueue.get()
                if stringToPrint == "Done.":
                    if printline != self.startingLine:
                        printline -= 1

                    self.screen.addstr(printline, 55, stringToPrint)
                else:
                    self.screen.addstr(printline, 4, stringToPrint)
                self.screen.clrtoeol()
                printline += 1
                if printline > 18:
                    printline = self.startingLine
                time.sleep(.1)
                self.screen.refresh()

    def join(self, timeout=None):
        self.stopUpdating.set()
        super(live_update, self).join(timeout)

def get_param(screen, prompt_string):
    screen.clear()
    screen.border(0)
    screen.addstr(2, 2, prompt_string)
    screen.refresh()
    input = screen.getstr(10, 10, 60)
    return input

def execute_cmd(cmd_string):
    system("clear")
    a = system(cmd_string)
    print ""
    if a == 0:
      print "Command executed correctly"
    else:
      print "Command terminated with error"
    raw_input("Press enter")
    print ""

def show_previous_analysis(screen):
    curses.endwin()
    sqlString = "select src AS 'Potential Infected Hosts', high_number_count_in_name AS 'Suspicious Domains', high_amount_of_ips_per_domain AS 'High IP Queries', sketchy_src AS 'Hyperactive Host', sketchy_browse AS 'Low Access Ratio', total_number_of_flags AS 'Total Flags Triggered' from malHosts"
    execute_cmd('mysql -u root --password=password --execute="'+sqlString+'" dynama')

def run_dynama(screen, analysisTimeInterval):
    printQueue = Queue.Queue()
    myAnalysis = main_analysis(analysisTimeInterval, printQueue)
    curses.endwin()
    myAnalysis.start_traffic_capture()
    time.sleep(2)
    screen.clear()
    screen.border(0)
    screen.addstr(1, 2, "DynaMA", curses.A_STANDOUT)
    screen.addstr(2, 2, "Press 'ctl + z' to exit.")
    screen.refresh()
    myAnalysis.start()
    time.sleep(2)
    myLiveUpdater = live_update(screen, printQueue, 3)
    myLiveUpdater.start()
    #screen.addstr(1, 15, "Waiting for q")
    dynamaChoice = screen.getch()
    if dynamaChoice == ord('q'):
        myAnalysis.join()
        myLiveUpdater.join()
    else:
        #screen.addstr(1, 30, "Done Waiting")
        pass


def show_databases(screen):
    screen.clear()
    screen.border(0)
    screen.addstr(2, 2, "Select a table to view")
    screen.addstr(4, 4, "1 - dnsPackets")
    screen.addstr(5, 4, "2 - dnsPackets2")
    screen.addstr(6, 4, "3 - multipleReturnIPs")
    screen.addstr(7, 4, "4 - Other tables")
    screen.addstr(8, 4, "5 - Exit")
    screen.refresh()

    userChoice = screen.getch()

    if userChoice == ord('1'):
        curses.endwin()
        execute_cmd('mysql -u root --password=password --execute="Select * from dnsPackets" dynama')
    elif userChoice == ord('2'):
        curses.endwin()
        execute_cmd('mysql -u root --password=password --execute="Select * from dnsPackets2" dynama')
    elif userChoice == ord('3'):
        curses.endwin()
        execute_cmd('mysql -u root --password=password --execute="Select * from multipleReturnIPs" dynama')
    else:
        pass

def main():

    analysisTimeInterval = 10
    userChoice = 0

    while userChoice != ord('5'):
        screen = curses.initscr()
        screen.clear()
        screen.border(0)
        screen.addstr(2, 2, "Welcome to DynaMA. Please enter a number", curses.A_UNDERLINE)
        screen.addstr(4, 4, "1 - Start packet capture and analysis")
        screen.addstr(5, 4, "2 - Show database tables")
        screen.addstr(6, 4, "3 - Show previous analysis")
        screen.addstr(7, 4, "4 - Set analysis time interval")
        screen.addstr(8, 4, "5 - Exit")
        screen.refresh()
        try:
            userChoice = screen.getch()

            if userChoice == ord('1'):
                curses.flash()
                curses.beep()
                run_dynama(screen, analysisTimeInterval)
            elif userChoice == ord('2'):
                show_databases(screen)
            elif userChoice == ord('3'):
                show_previous_analysis(screen)
            elif userChoice == ord('4'):
                analysisTimeInterval = get_param(screen, "Enter an numeric value:")
        except:
            screen.clear()
            screen.addst(2, 2, "An unexpcted error has occured.")
            break



    curses.endwin()

if __name__ == '__main__':
    main()
