#pragma once
#ifndef DOT11_H
#define DOT11_H
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

using namespace std;

#pragma pack(push,1)

struct fcontrol{
    unsigned int protver : 2;
    unsigned int type : 2;
    unsigned int subtype : 4;
    unsigned int tods : 1;
    unsigned int fromds : 1;
    unsigned int moref : 1;
    unsigned int retry : 1;
    unsigned int power : 1;
    unsigned int mored : 1;
    unsigned int wep : 1;
    unsigned int rsvd : 1;
};

struct dot11_header
{
    struct fcontrol fc;
    uint16_t duration;
    uint8_t dest[6]; //dest
    uint8_t sour[6]; //source
    uint8_t bssid[6]; //bssid
    uint16_t seq;
};

struct beacon_fixed
{
    uint8_t timestamp[8];
    uint16_t interval;
    uint16_t capab;


};
struct reasso_fixed
{
    uint8_t timestamp[8];
    uint16_t interval;
    uint16_t capab;
};
struct reasso_fixed2
{
    uint16_t capab;
    uint16_t interval;
    uint8_t current[6];

};

struct ssid
{
    uint8_t ssid_num;
    uint8_t ssid_len;
    //vector<uint8_t> essid;
};


struct ap{

    //vector<uint8_t> bssid;
    vector<uint8_t> essid;
    uint8_t beacon;
    uint8_t channel;
    int8_t pwr;
    uint8_t essid_len;
    uint8_t enc;
    uint8_t cipher;
};

struct station{

    uint8_t mac[6];
    uint8_t ip[4];

};

uint8_t* make_beacon(vector<uint8_t> mac,struct ap select,uint8_t* pk_size,int num);
uint8_t* make_reasso(vector<uint8_t> mac,struct ap select,uint8_t* pk_size,int num);
uint8_t* make_reasso2(vector<uint8_t> mac,struct ap select,uint8_t* pk_size);
uint8_t* make_deauth(vector<uint8_t> mac,uint8_t *size);
uint8_t* make_disasso(vector<uint8_t> mac,uint8_t *size);

#pragma pack(pop)
#endif // DOT11_H
