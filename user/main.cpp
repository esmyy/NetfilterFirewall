#include "firewall.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    firewall w;
    w.setWindowTitle("NetFilterFirewall");
    w.setWindowIcon(QIcon(":/images/logo.ico"));
    w.showMaximized();
    w.show();

    return a.exec();
}
