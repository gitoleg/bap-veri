#!/usr/bin/python

import sys,getopt
import sqlite3
import matplotlib.pyplot as plt

def extract_ids(c, arch):
    q = "SELECT * FROM task WHERE Id IN \
    (SELECT Id FROM info WHERE Arch = '%s' And Kind = 'Trace')" % arch
    c.execute(q)
    return c.fetchall()

def extract_stat(c, task_id):
    q = "SELECT * FROM dynamic_data WHERE Id_task = '%d'" % task_id
    c.execute(q)
    return c.fetchall()

def cnt_suc(c, task_id):
    suc = 0
    stats = extract_stat(c, task_id)
    for data in stats:
        suc += int(data[3])
    return suc

def calc(c, arch):
    tasks = extract_ids(c, arch)
    x = []
    for task in tasks:
        task_id = long(task[0])
        task_name = task[1]
        stats = extract_stat(c, task_id)
        suc,und,uns,unk = 0,0,0,0
        for data in stats:
            suc += int(data[3])
            und += int(data[4])
            uns += int(data[5])
            unk += int(data[6])
        tot = suc + und + uns + unk
        x.append((task_name,suc,uns,tot))
    return x

def draw(db, arch):
    print "%s %s" % (db, arch)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    res = calc(conn.cursor(), arch)
    conn.close ()
    names = map((lambda x: x[0]), res)
    sucs = map((lambda x: float(x[1]) / x[3]), res)
    x = range(len(names))
    fig = plt.figure(0)
    fig.canvas.set_window_title('')
    plt.xticks(x, names)
    plt.xticks(rotation=70)
    plt.ylim([0.8, 1.0])
    sucs, = plt.plot(x, sucs)
    plt.legend([sucs],[arch])
    plt.show()

if __name__ == "__main__":
    arch = ''
    db = ''
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["arch=", "db="])
    except getopt.GetoptError:
        print "usage: draw.py --arch=arch-name --db=database"
        sys.exit(2)
    for opt,arg in opts :
        if opt in ("-a", "--arch"):
            arch = arg
        elif opt in ("--db"):
            db = arg
    draw(db, arch)
