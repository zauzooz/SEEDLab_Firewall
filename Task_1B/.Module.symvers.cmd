cmd_/home/nnt/SEEDLab/Firewall/Task_1B/Module.symvers := sed 's/\.ko$$/\.o/' /home/nnt/SEEDLab/Firewall/Task_1B/modules.order | scripts/mod/modpost -m -a  -o /home/nnt/SEEDLab/Firewall/Task_1B/Module.symvers -e -i Module.symvers   -T -
