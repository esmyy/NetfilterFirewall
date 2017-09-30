#include "firewall.h"
#include "ui_firewall.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <getopt.h>

#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 2

#define FW_CDEV_NAME "/dev/NetfilterFirewall"
/**
 * @brief firewall::firewall
 * @param parent
 */
firewall::firewall(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::firewall) {
    ui->setupUi(this);
    // my init
    initRuleListTable();

    // statusBar初始化
    statusLabel  = new QLabel();
    statusLabel->setMinimumSize(200,20);
    statusLabel->setStyleSheet("background-color: rgb(203, 196, 196);");
    statusLabel->setAlignment(Qt::AlignLeft);
    statusLabel->setText("copyright © 2017,fangnan");
    ui->statusBar->addWidget(statusLabel);

    rulesFilename = "rules.dat";
    fd = open(FW_CDEV_NAME, O_RDWR);
    if(fd <= 0) {
        warningBox("Error while openning " + QString(FW_CDEV_NAME));
    } /*else {
        statusLabel->setText("Successful openning " + QString(FW_CDEV_NAME));
    }*/

    // config file struct like: sip:dip:sport:dport:protocolnumber:smask:dmask:0:0\n
    // read rules
    QFile file(rulesFilename);
    QString line;

    Node item;
    // read int rules
    if(QFileInfo::exists(rulesFilename) && file.open(QFile::ReadOnly)) {
        item.next = NULL;
        while(!file.atEnd()) {
           line = QString::fromLocal8Bit(file.readLine().data());
           item.sip =  line.section(":",0,0).trimmed().toUInt();
           item.dip = line.section(":",1,1).trimmed().toUInt();
           item.sport = line.section(":",2,2).trimmed().toUShort();
           item.dport = line.section(":",3,3).trimmed().toUShort();
           item.protocol = line.section(":",4,4).trimmed().toUShort();
           item.sMask = line.section(":",5,5).trimmed().toShort();
           item.dMask = line.section(":",6,6).trimmed().toShort();


           if(line.section(":",7,7).trimmed().toUShort() == 1) {
                item.isPermit = true;
           } else {
               item.isPermit = false;
           }

           if(line.section(":",8,8).trimmed().toUShort() == 1) {
               item.isLog = true;
           } else {
               item.isLog = false;
           }

           ruleList.push_back(item);
        }
        file.close();
    }

    // add rules to table widget, and send to kernel
    for(int i = 0, len = ruleList.length(); i < len; i++) {
        addARuleToTable(ruleList[i],i);
        ioctl(fd, FW_ADD_RULE, &ruleList[i]);
    }
    // send to kernel,
}

/**
 * add a rule to the table
 * @brief firewall::addARuleToTable
 * @param item: the rule to add
 * @param i: add as row i, i from 0
 */
void firewall::addARuleToTable(Node item,unsigned int i) {
    /* so strange, if get dip follow get  sip, then dip would be wrong,something unexpected */
    QString sip;
    QString dip;
    QString protocol;
    QTableWidget *ruleListTable = ui->ruleListTable;
    // why sip is the same as dip ? why I add a rule
    sip = get_string_ip_addr(item.sip);
//    warningBox(sip); // so ruleList sip is wrong while add
    protocol = getProtocolName(item.protocol);
    if(item.sMask > 0) {
        sip += QString("/") + QString::number(item.sMask);
    }

    // why,dip lika 192.168.90.9is correct,why ? why? why cover?
//    warningBox(dip);
    dip = get_string_ip_addr(item.dip);
    if(item.dMask > 0) {
        dip += QString("/") + QString::number(item.dMask);
    }

    // check rows, if rows is not enough, add one rows
    unsigned int len = ruleListTable->rowCount();
    if(len == i) { //
       ruleListTable->setRowCount(i + 1);
    }

    // set item
    ruleListTable->setItem(i,0,new QTableWidgetItem(sip));
    ruleListTable->setItem(i,1,new QTableWidgetItem(dip));
    if(item.sport) {
        ruleListTable->setItem(i,2,new QTableWidgetItem(QString::number(item.sport)));
    } else {
        ruleListTable->setItem(i,2,new QTableWidgetItem("ANY"));
    }
    if(item.dport) {
        ruleListTable->setItem(i,3,new QTableWidgetItem(QString::number(item.dport)));
    } else {
        ruleListTable->setItem(i,3,new QTableWidgetItem("ANY"));
    }
    ruleListTable->setItem(i,4,new QTableWidgetItem(protocol));

    if(item.isPermit) {
        ruleListTable->setItem(i,5,new QTableWidgetItem("Permit"));
    } else {
        ruleListTable->setItem(i,5,new QTableWidgetItem("Reject"));
    }

    if(item.isLog) {
        ruleListTable->setItem(i,6,new QTableWidgetItem("true"));
    } else {
        ruleListTable->setItem(i,6,new QTableWidgetItem("false"));
    }
}

firewall::~firewall() {
    delete ui;
}

/* for ip and port, 0 is as any */
// add

/**
 * @brief firewall::on_addBtn_clicked
 *
 * function: add a rule, refresh the table, notice the kernel
 */
void firewall::on_addBtn_clicked(){

    Node item;
    QString sIPstr = ui->sourceIPInput->text().trimmed();
    QString dIPstr = ui->destIPInput->text().trimmed();

    // checked ip
    if(!check_ip(sIPstr) || !check_ip(dIPstr)) {
       warningBox("IP is not correct, please check your ip input.");
       return;
    }

    // checked port
    QString sPortStr = ui->sourcePortInput->text().trimmed();
    QString dPortStr = ui->destPortInput->text().trimmed();
    if(!check_port(sPortStr) || !check_port(dPortStr)){
        warningBox("Port is not correct, please check your port input.");
        return;
    }

    // get ip why sip result is the same as dip ?
    // if a function return a string, and was call more than one times continuity, the result might be wrong, why?
    // if i move sip and dip together, it would be wrong!
    char *csip = sIPstr.toLocal8Bit().data();
    item.sip = inet_addr(csip);
    item.sport = get_port(sPortStr);


    // get port
    char *cdip = dIPstr.toLocal8Bit().data();
    item.dip = inet_addr(cdip);
    item.dport = get_port(dPortStr);


    // get protocol, 0 is as any
    QString protocol = ui->protocolComboBox->currentText().trimmed();
    item.protocol = getProtocolNumber(protocol.toLocal8Bit().data());
    // if ICMP, port as any
    if(protocol == "ICMP") {
        item.sport = 0;
        item.dport = 0;
    }

    // if value 0, means not a subnet mask, else as subnet mask number
    item.sMask = get_subnet_mask_number(sIPstr);
    item.dMask = get_subnet_mask_number(dIPstr);
    if(ui->buttonGroup->checkedButton()->objectName().trimmed() == "permit") {
        item.isPermit = true;
    } else {
        item.isPermit = false;
    }
    if(ui->writeLogChecked->isChecked()) {
        item.isLog = true;
    } else {
        item.isLog = false;
    }

    // judge if has the same record, ip ,port, protocol all the same
    bool isExisted = false;
    for(int i = 0,len = ruleList.length(); i < len; i++) {
        if(ruleList[i].sip != item.sip || ruleList[i].dip != item.dip) {
            continue;
        }

        if(ruleList[i].protocol != item.protocol) {
            continue;
        }

        // if ICMP, not need to check port
        if(item.protocol == IPPROTO_ICMP) {
            isExisted = true;
            break;
        }

        if(ruleList[i].sport != item.sport || ruleList[i].dport != item.dport) {
            continue;
        }

        isExisted = true;
        break;
    }

    if(isExisted) {
        warningBox("There is a consistent record! So you are failed to add!");
        return;
    }

    // add to ruleList
    ruleList.append(item);

    // add to table shows
    unsigned int len = ruleList.length();
    addARuleToTable(item,len -1);

    // let ke rnel know, send item to kernel
    ioctl(fd, FW_ADD_RULE, &item);
}

/**
 * @brief firewall::refreshRulesFile
 *
 * rewrite the rules file with current ruleList
 */
void firewall::refreshRulesFile() {
    // write into rule file

    QFile file(rulesFilename);
    if(file.open(QFile::WriteOnly)) {
        QTextStream out(&file);
        QString str;
        Node item;
        for(int i = 0, len = ruleList.length(); i < len; i++) {
            item = ruleList[i];
            QString str = QString::number(item.sip) + ":"  + QString::number(item.dip) + ":";
            str += QString::number(item.sport) + ":";
            str += QString::number(item.dport) + ":";
            str += QString::number(item.protocol) + ":";
            str += QString::number(item.sMask) + ":";
            str += QString::number(item.dMask) + ":";
            if(item.isPermit) {
                str += "1:";
            } else {
                str += "0:";
            }

            if(item.isLog) {
                str += "1\n";
            } else {
                str += "0\n";
            }
            out << str;
        }
        file.close();
    }
}

// delete record
/**
 * @brief firewall::on_deleteBtn_clicked
 *
 * function: delete a rule, the rule is select in table
 */
void firewall::on_deleteBtn_clicked(){

    // check rules length
    // the table row count is not equal with ruleList, we should judge by ruleList's length
    int len = ruleList.length();
    if(len <= 0) {
        warningBox("WOW! Nothing to delete.");
        return;
    }

    // check current row
    int row = ui->ruleListTable->currentRow();
    if(row < 0) {
        warningBox("Not any row select yet, please select the row you want to delete.");
        return;
    }

    // check is out of range
    if(row >= len) {
        // out of range
        return;
    }
    // checked delete again
    bool reply = questionBox("delete checked","You are going to delete the selected row, sure ?","Yes, do it!", "No, go back.");
    if(!reply) {
        return;
    }

    // delete in the table, if delete a row, the rowCount will auto reduce 1
    ui->ruleListTable->removeRow(row);

    // delete in the ruleList, if delete the last row, the program stop, it is because ioctl position wrong
    // first notice kernel then remove
    // notice kernel
    ioctl(fd, FW_DEL_RULE, &ruleList[row]);
    ruleList.remove(row);
}

/**
 * @brief firewall::on_clearBtn_clicked
 * function: clear all the rule in list and kernel
 */
void firewall::on_clearBtn_clicked(){

    // question
    bool reply = questionBox("clear check","Are you sure to clear all the filter rules ?", "Yes, clear!", "No, go back!");
    if(!reply){
        return;
    }

    // clear the ruleList
    ruleList.clear();

    // clear the table
    ui->ruleListTable->clear();
    // rules file clear, won't clear the file, only when you choose to clear while close.
//    QFile file(rulesFilename);
//    if(QFileInfo::exists(rulesFilename) && file.open(QFile::WriteOnly)) {
//        file.close();
//    }

    // notice kernel to clear
    Node item = {0,0,0,0,0,0,0,false,false,NULL};
    ioctl(fd, FW_CLEAR_RULE,&item);
}

/**
 * @brief firewall::inet_addr
 * @param str
 * @return
 */
unsigned int firewall::inet_addr(char *str) {
    int a,b,c,d;
    char arr[4];
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int*)arr;
}

// checked ip,
// juege 0 - 255;
/**
 * @brief firewall::check_ip
 * @param ipstr
 * @return if is a correct ip or ip with subnet mask, return true, else return false
 */
bool firewall::check_ip(QString ipstr){
    QRegExp reg("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(\\/[0-9]{1,2})?$");
    if(!reg.exactMatch(ipstr)) {
        return false;
    }

    char *str = ipstr.toLocal8Bit().data();
    int a,b,c,d;
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);

    // judge if is a correct ip
    if(a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
        return false;
    }

    return true;
}

// checked port
/**
 * @brief firewall::check_port
 * @param portStr
 * @return true if is a port in range, else return false
 */
bool firewall::check_port(QString portStr){
    QRegExp reg("^[0-9]{1,5}$");
    if(!reg.exactMatch(portStr)){
        return false;
    }

    // if use to ushort, maybe not true
    unsigned int t = portStr.toUInt();
    if(t >= MAX_PORT){
        return false;
    }
    return true;
}

// get port
/**
 * @brief firewall::get_port
 * @param portStr: the string port, like "8888"
 * @return return the number of port, like 8888
 */
unsigned short firewall::get_port(QString portStr){
    unsigned short port = portStr.toUShort();
    return port;
}

/**
 * @brief firewall::get_subnet_mask_number
 * @param ipstr: the ip string, like 192.168.89.45/24
 * @return return the number or net part lenth, like 24,
 */
unsigned short firewall::get_subnet_mask_number(QString ipstr){
    QRegExp reg("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\/((0-9)|([0-2][0-9])|(3[012]))$");
    if(!reg.exactMatch(ipstr)) {
        return 0;
    }

    // get subnet mask number of bits
    unsigned short mask = ipstr.mid(ipstr.lastIndexOf('/') + 1,-1).toUShort();

    // mask only permit 8,16 and 24.
    if(mask == 8 || mask == 16 || mask == 24) {
        return mask;
    }

    return 0;
}

/**
 * @brief firewall::getProtocolNumber
 * @param protocol: protocol name, like "TCP","UDP"
 * @return the standard number of the protocol, like IPPROTO_TCP
 */
unsigned short firewall::getProtocolNumber(QString protocol) {

    // default as any, use 0
    unsigned short t = 0;
    if(QString::compare(protocol,"TCP") == 0){
        t = IPPROTO_TCP;
    } else if(QString::compare(protocol,"UDP") == 0){
        t = IPPROTO_UDP;
    } else if(QString::compare(protocol,"ICMP") == 0){
        t = IPPROTO_ICMP;
    }
    return t;
}

/**
 * @brief firewall::getProtocolName
 * @param protocolNumber: the u"nsigned short protocol number,like IPPROTO_TCP
 * @return return the string like "IPPROTO_TCP"
 */
QString firewall::getProtocolName(unsigned short protocolNumber) {
    QString t = "ANY";
    switch(protocolNumber){
        case IPPROTO_TCP:
            t = "TCP";
            break;
        case IPPROTO_UDP:
            t = "UDP";
            break;
        case IPPROTO_ICMP:
            t = "ICMP";
            break;
        default:

            break;
    }

    return t;
}

/**
 * @brief firewall::warningBox
 * @param str: the message to show
 */
void firewall::warningBox(QString str){
    QMessageBox box(QMessageBox::Warning, "warning",str);
    box.setStandardButtons(QMessageBox::Ok);
    box.setButtonText(QMessageBox::Ok,QString("get it!"));
    box.exec();
}

/**
 * @brief firewall::questionBox
 * @param title: the box title
 * @param msg: the message to whow
 * @param yesStr: Yes button content
 * @param noStr: No button content
 * @return
 */
bool firewall::questionBox(QString title,QString msg,QString yesStr,QString noStr){
    QMessageBox reply(QMessageBox::Question, title,msg);
    reply.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    reply.setButtonText(QMessageBox::Yes,QString(yesStr));
    reply.setButtonText(QMessageBox::No,QString(noStr));
    reply.setDefaultButton(QMessageBox::No);
    if (reply.exec() == QMessageBox::Yes) {
       return true;
    } else {
       return false;
    }
}

/*
 * init the table to show rules
 */
void firewall::initRuleListTable() {
    QStringList header;
    QTableWidget *ruleListTable = ui->ruleListTable;

    ruleListTable->setRowCount(15);
    ruleListTable->setColumnCount(7);
    header << "source ip" << "dest ip" << "S port" << "D port" << "protocol" << "action" << "log";
    ruleListTable->setWindowTitle("rule list table");
    ruleListTable->setHorizontalHeaderLabels(header);
    ruleListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);   // set readonly
    ruleListTable->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择的模式为单选择
    ruleListTable->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一行
    ruleListTable->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:lightblue;color: black;padding-left: 4px;border: 1px solid #6c6c6c;}");    //设置表头字体，颜色，模式
    ruleListTable->verticalHeader()->setStyleSheet("QHeaderView::section {  background-color:skyblue;color: black;padding-left: 4px;border: 1px solid #6c6c6c}");   //设置纵列的边框项的字体颜色模式等
    ruleListTable->horizontalHeader()->setStretchLastSection(true);

    ruleListTable->setColumnWidth(0,160);
    ruleListTable->setColumnWidth(1,160);
    ruleListTable->setColumnWidth(2,60);
    ruleListTable->setColumnWidth(3,60);
    ruleListTable->setColumnWidth(4,80);
    ruleListTable->setColumnWidth(5,60);
    ruleListTable->setColumnWidth(6,60);
//    ruleListTable->setColumnWidth(7,60);
//    ruleListTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    ruleListTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
}


/*
 * get ip as a string
 * unsigned int ip number to string
 */
QString firewall::get_string_ip_addr(unsigned int ip) {
    unsigned int t = 0x000000ff;
    if(ip == 0) { // ANY
        return "ANY";
    }

    QString re;
    re.append(QString::number(ip & t)).append(".");
    re.append(QString::number((ip >> 8) & t)).append(".");
    re.append(QString::number((ip >> 16) & t)).append(".");
    re.append(QString::number((ip >> 24) & t)).append("\0");
    return re;
}

// close event
void firewall::closeEvent(QCloseEvent *event) {
    bool reply = questionBox("close check","You are going to close this program, sure?","Yes,Bye!","No");
    if(!reply){
        event->ignore();
        return;
    }
    ::close(fd);
    event->accept();
}

/**
 * @brief firewall::on_rewriteDefaultRulesFile_clicked
 * rewrite the default
 */
void firewall::on_rewriteDefaultRulesFile_clicked(){
    bool reply = questionBox("refresh rules file check","You are going rewrite the defaule rules file with current table, sure?","Yes, do it!","No!");
    if(!reply){
        return;
    }
    refreshRulesFile();
}
