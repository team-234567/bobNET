#include "dot11.h"
#include "radiotap.h"
#include <map>
#include <string.h>
#include <arpa/inet.h>



uint8_t* make_beacon(vector<uint8_t> mac,struct ap select,uint8_t* pk_size,int num){

    uint8_t *packet;
    struct radiotap beacon_radio;
    beacon_radio.version=0;
    beacon_radio.pad=0;
    beacon_radio.len=8;
    beacon_radio.present=0;
    //memset((uint8_t*)&beacon_radio+4,0,beacon_radio.len-4);

    struct dot11_header beacon_header;


    for(int i=0;i<6;i++){
        beacon_header.bssid[i]=mac.at(i);
        beacon_header.sour[i]=mac.at(i);}
    //memset(beacon_header.sour,0x11,6);
    //memset(beacon_header.bssid,0x11,6);
    memset(beacon_header.dest,0xFF,6);
    beacon_header.duration=0x0000;
    beacon_header.seq=0x0000;

    beacon_header.fc.protver=0;
    beacon_header.fc.type=0;
    beacon_header.fc.subtype=8;
    beacon_header.fc.tods=0;
    beacon_header.fc.fromds=0;
    beacon_header.fc.moref=0;
    beacon_header.fc.retry=0;
    beacon_header.fc.power=0;
    beacon_header.fc.mored=0;
    beacon_header.fc.wep=0;
    beacon_header.fc.rsvd=0;

    struct beacon_fixed beacon_body;
    memset(beacon_body.timestamp,0x00,8);
    beacon_body.interval=0;
    beacon_body.capab=0;

    struct ssid beacon_ssid;
    beacon_ssid.ssid_num=0;
    beacon_ssid.ssid_len=select.essid_len+2;
    //beacon_ssid.ssid_len=select.essid_len;

    const int size = beacon_ssid.ssid_len;

    uint8_t ssid[size];
    int temp=0;
    for(auto i=select.essid.begin();i!=select.essid.end();i++)
           {
        ssid[temp++]=*i;
    }

    ssid[temp++]=0x2d;
    ssid[temp]=48+num;


    *(pk_size)=beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(beacon_ssid)+size;
    packet=(uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

    memcpy(packet,(uint8_t*)&beacon_radio,beacon_radio.len);
    memcpy(packet+beacon_radio.len,(uint8_t*)&beacon_header,sizeof(struct dot11_header));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header),(uint8_t*)&beacon_body,sizeof(struct beacon_fixed));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed),(uint8_t*)&beacon_ssid,sizeof(struct ssid));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(struct ssid),(uint8_t*)ssid,size);

    /*
    for(int i=0;i<*pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");*/

    return packet;


}

uint8_t* make_deauth(vector<uint8_t> mac,uint8_t* size){



    uint8_t* packet;

    struct radiotap deauth_radio;

    deauth_radio.version=0x00;
    deauth_radio.pad=0;
    deauth_radio.len=8;
    deauth_radio.present=0;
    //packet=(uint8_t*)&deauth_radio;
    struct dot11_header deauth_header;

    for(int i=0;i<6;i++){
        deauth_header.bssid[i]=mac.at(i);
        deauth_header.sour[i]=mac.at(i);}

    memset(deauth_header.dest,0xFF,6);
    deauth_header.duration=0x0000;
    deauth_header.seq=0x0000;

    deauth_header.fc.protver=0;
    deauth_header.fc.type=0;
    deauth_header.fc.subtype=0xc;
    deauth_header.fc.tods=0;
    deauth_header.fc.fromds=0;
    deauth_header.fc.moref=0;
    deauth_header.fc.retry=0;
    deauth_header.fc.power=0;
    deauth_header.fc.mored=0;
    deauth_header.fc.wep=0;
    deauth_header.fc.rsvd=0;

    uint16_t reason_code =0x0007;
    int pk_size=deauth_radio.len+sizeof(struct dot11_header)+sizeof(uint16_t);
    packet=(uint8_t*)malloc(sizeof(uint8_t)*pk_size);
    memcpy(packet,(uint8_t*)&deauth_radio,deauth_radio.len);
    memcpy(packet+deauth_radio.len,(uint8_t*)&deauth_header,sizeof(struct dot11_header));
    memcpy(packet+deauth_radio.len+sizeof(struct dot11_header),(uint8_t*)&reason_code,sizeof(uint16_t));


/*
    for(int i=0;i<pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");
*/

    *size= pk_size;

    return packet;

}
uint8_t* make_disasso(vector<uint8_t> mac,uint8_t* size){



    uint8_t* packet;

    struct radiotap disasso_radio;

    disasso_radio.version=0x00;
    disasso_radio.pad=0;
    disasso_radio.len=8;
    disasso_radio.present=0;
    //packet=(uint8_t*)&disasso_radio;
    struct dot11_header disasso_header;

    for(int i=0;i<6;i++){
        disasso_header.bssid[i]=mac.at(i);
        disasso_header.sour[i]=mac.at(i);}

    memset(disasso_header.dest,0xFF,6);
    disasso_header.duration=0x0000;
    disasso_header.seq=0x0000;

    disasso_header.fc.protver=0;
    disasso_header.fc.type=0;
    disasso_header.fc.subtype=0xa;
    disasso_header.fc.tods=0;
    disasso_header.fc.fromds=0;
    disasso_header.fc.moref=0;
    disasso_header.fc.retry=0;
    disasso_header.fc.power=0;
    disasso_header.fc.mored=0;
    disasso_header.fc.wep=0;
    disasso_header.fc.rsvd=0;

    uint16_t reason_code =0x0007;
    int pk_size=disasso_radio.len+sizeof(struct dot11_header)+sizeof(uint16_t);
    packet=(uint8_t*)malloc(sizeof(uint8_t)*pk_size);
    memcpy(packet,(uint8_t*)&disasso_radio,disasso_radio.len);
    memcpy(packet+disasso_radio.len,(uint8_t*)&disasso_header,sizeof(struct dot11_header));
    memcpy(packet+disasso_radio.len+sizeof(struct dot11_header),(uint8_t*)&reason_code,sizeof(uint16_t));


/*
    for(int i=0;i<pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");
*/

    *size= pk_size;

    return packet;

}

uint8_t* make_reasso(vector<uint8_t> mac,struct ap select,uint8_t* pk_size,int num){

    uint8_t *packet;
    struct radiotap reasso_radio;
    reasso_radio.version=0;
    reasso_radio.pad=0;
    reasso_radio.len=8;
    reasso_radio.present=0;
    //memset((uint8_t*)&beacon_radio+4,0,beacon_radio.len-4);

    struct dot11_header reasso_header;


    for(int i=0;i<6;i++){
        reasso_header.bssid[i]=mac.at(i);
        reasso_header.sour[i]=mac.at(i);}
    //memset(reasso_header.sour,0x11,6);
    //memset(reasso_header.bssid,0x11,6);
    memset(reasso_header.dest,0xFF,6);
    reasso_header.duration=0x0000;
    reasso_header.seq=0x0000;

    reasso_header.fc.protver=0;
    reasso_header.fc.type=0;
    reasso_header.fc.subtype=0x2;
    reasso_header.fc.tods=0;
    reasso_header.fc.fromds=0;
    reasso_header.fc.moref=0;
    reasso_header.fc.retry=0;
    reasso_header.fc.power=0;
    reasso_header.fc.mored=0;
    reasso_header.fc.wep=0;
    reasso_header.fc.rsvd=0;

    struct reasso_fixed reasso_body;
    memset(reasso_body.timestamp,0x00,8);
    reasso_body.interval=0;
    reasso_body.capab=0;

    struct ssid beacon_ssid;
    beacon_ssid.ssid_num=0;
    beacon_ssid.ssid_len=select.essid_len+2;
    //beacon_ssid.ssid_len=select.essid_len;

    const int size = beacon_ssid.ssid_len;

    uint8_t ssid[size];
    int temp=0;
    for(auto i=select.essid.begin();i!=select.essid.end();i++)
           {
        ssid[temp++]=*i;
    }

    ssid[temp++]=0x2d;
    ssid[temp]=48+num;


    *(pk_size)=reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(beacon_ssid)+size;
    packet=(uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

    memcpy(packet,(uint8_t*)&reasso_radio,reasso_radio.len);
    memcpy(packet+reasso_radio.len,(uint8_t*)&reasso_header,sizeof(struct dot11_header));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header),(uint8_t*)&reasso_body,sizeof(struct beacon_fixed));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed),(uint8_t*)&beacon_ssid,sizeof(struct ssid));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(struct ssid),(uint8_t*)ssid,size);

    /*
    for(int i=0;i<*pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");*/

    return packet;


}

uint8_t* make_reasso2(vector<uint8_t> mac,struct ap select,uint8_t* pk_size){

    uint8_t *packet;
    struct radiotap reasso_radio;
    reasso_radio.version=0;
    reasso_radio.pad=0;
    reasso_radio.len=8;
    reasso_radio.present=0;


    struct dot11_header reasso_header;


    for(int i=0;i<6;i++){
        reasso_header.bssid[i]=mac.at(i);
        reasso_header.sour[i]=mac.at(i);}

    memset(reasso_header.dest,0xFF,6);
    reasso_header.duration=0x0000;
    reasso_header.seq=0x0000;

    reasso_header.fc.protver=0;
    reasso_header.fc.type=0;
    reasso_header.fc.subtype=0x2;
    reasso_header.fc.tods=0;
    reasso_header.fc.fromds=0;
    reasso_header.fc.moref=0;
    reasso_header.fc.retry=0;
    reasso_header.fc.power=0;
    reasso_header.fc.mored=0;
    reasso_header.fc.wep=0;
    reasso_header.fc.rsvd=0;

    struct reasso_fixed2 reasso_body;

    reasso_body.interval=0;
    reasso_body.capab=0;
    for(int i=0;i<6;i++){
        reasso_body.current[i]=mac.at(i);}

    struct ssid beacon_ssid;
    beacon_ssid.ssid_num=0;

    beacon_ssid.ssid_len=select.essid_len;

    const int size = beacon_ssid.ssid_len;

    uint8_t ssid[size];
    int temp=0;
    for(auto i=select.essid.begin();i!=select.essid.end();i++)
           {
        ssid[temp++]=*i;
    }




    *(pk_size)=reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct reasso_fixed2)+sizeof(beacon_ssid)+size;
    packet=(uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

    memcpy(packet,(uint8_t*)&reasso_radio,reasso_radio.len);
    memcpy(packet+reasso_radio.len,(uint8_t*)&reasso_header,sizeof(struct dot11_header));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header),(uint8_t*)&reasso_body,sizeof(struct reasso_fixed2));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct reasso_fixed2),(uint8_t*)&beacon_ssid,sizeof(struct ssid));
    memcpy(packet+reasso_radio.len+sizeof(struct dot11_header)+sizeof(struct reasso_fixed2)+sizeof(struct ssid),(uint8_t*)ssid,size);

    /*
    for(int i=0;i<*pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");*/

    return packet;


}

uint8_t* make_rts(vector<uint8_t> mac, struct ap select, uint8_t* pk_size) {

	uint8_t *packet;
	struct radiotap rts_radio;
	rts_radio.version = 0;
	rts_radio.pad = 0;
	rts_radio.len = 8;
	rts_radio.present = 0;


	struct dot11_header2 rts_header;


	for (int i = 0; i < 6; i++) {
		rts_header.transmitter[i] = mac.at(i);
	}

	memset(rts_header.receiver, 0xFF, 6);
	rts_header.duration = 0x0000;
	rts_header.fcs = 0x0000;

	rts_header.fc.protver = 0;
	rts_header.fc.type = 1;
	rts_header.fc.subtype = 12;
	rts_header.fc.tods = 0;
	rts_header.fc.fromds = 0;
	rts_header.fc.moref = 0;
	rts_header.fc.retry = 0;
	rts_header.fc.power = 0;
	rts_header.fc.mored = 0;
	rts_header.fc.wep = 0;
	rts_header.fc.rsvd = 0;






	*(pk_size) = rts_radio.len + sizeof(struct dot11_header2);
	packet = (uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

	memcpy(packet, (uint8_t*)&rts_radio, rts_radio.len);
	memcpy(packet + rts_radio.len, (uint8_t*)&rts_header, sizeof(struct dot11_header2));


	/*
	for(int i=0;i<*pk_size;i++)
		printf("%02x",*(packet+i));
	printf("\n");*/

	return packet;


}
uint8_t* make_cts(vector<uint8_t> mac, struct ap select, uint8_t* pk_size) {

	uint8_t *packet;
	struct radiotap cts_radio;
	cts_radio.version = 0;
	cts_radio.pad = 0;
	cts_radio.len = 8;
	cts_radio.present = 0;


	struct dot11_header2 cts_header;


	for (int i = 0; i < 6; i++) {
		cts_header.transmitter[i] = mac.at(i);
	}

	memset(cts_header.receiver, 0xFF, 6);
	cts_header.duration = 0x0000;
	cts_header.fcs = 0x0000;

	cts_header.fc.protver = 0;
	cts_header.fc.type = 1;
	cts_header.fc.subtype = 11;
	cts_header.fc.tods = 0;
	cts_header.fc.fromds = 0;
	cts_header.fc.moref = 0;
	cts_header.fc.retry = 0;
	cts_header.fc.power = 0;
	cts_header.fc.mored = 0;
	cts_header.fc.wep = 0;
	cts_header.fc.rsvd = 0;






	*(pk_size) = cts_radio.len + sizeof(struct dot11_header2);
	packet = (uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

	memcpy(packet, (uint8_t*)&cts_radio, cts_radio.len);
	memcpy(packet + cts_radio.len, (uint8_t*)&cts_header, sizeof(struct dot11_header2));


	/*
	for(int i=0;i<*pk_size;i++)
		printf("%02x",*(packet+i));
	printf("\n");*/

	return packet;


}

