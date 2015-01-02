mod_cdr_mysql
=============

FreeSWITCH Module CDR MYSQL

apt-get install libmysql++-dev

Just copy this folder in /usr/local/src/freeswitch/src/mod/event_handlers/

      make
      make install
      
Add it to autoloadconfig/modules.conf.

Edit the file cdr_mysql.conf with your DB settings.
Add the cdr_mysql.conf file to autoloadconfig folder. 

Restart FreeSWITCH

