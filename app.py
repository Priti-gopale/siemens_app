from flask import Flask, render_template, request
import os
from matplotlib.pyplot import title
import pandas as pd
# import matplotlib.pyplot as plt
import datetime

app=Flask(__name__)

data1=pd.read_csv('static/DefectsData.csv')
data2=pd.read_csv('static/Objective OWASP Top 10 (2017).csv')

occur=pd.read_csv('static/security.csv')
# overdue_df1=pd.DataFrame
# overdue_df2=pd.DataFrame
# string_seg=""

sla=pd.read_csv('static/SLA.csv')
expired=[]
non_expired= []
seg1={}
date_today=str(datetime.date.today())
@app.route('/',methods = ['GET','POST'])
def index():
    if request.method =='POST':
        file=request.files['csvfile']
        if not os.path.isdir('static'):
            os.mkdir('static')
        filepath=os.path.join('static',file.filename)
        file.save(filepath)

        return 'The file name of the uploaded file is:{}'.format(file.filename)
    # print("DEBUGGING")
    
    print(date_today)
    l=[]        
    for i in range(data1.shape[0]):
        dateA=str(date_today)             
        dateA=dateA.split("-")
        dateA=datetime.date(int(dateA[0]),int(dateA[1]),int(dateA[2]))
        dateB=(data1['Created_date'][i])
        dateB=dateB.split("-")
        dateB=datetime.date(int(dateB[2]),int(dateB[1]),int(dateB[0]))
        l.append((dateA-dateB).days)
    
    l2=[]
    for i in range(data2.shape[0]):
        dateX=str(date_today)             
        dateX=dateX.split("-")
        dateX=datetime.date(int(dateX[0]),int(dateX[1]),int(dateX[2]))
        dateY=(data2['First Detected'][i])
        dateY=dateY.split("-")
        dateY=datetime.date(int(dateY[2]),int(dateY[1]),int(dateY[0]))
        l2.append((dateX-dateY).days)

    data1[str(date_today)]=l
    data2[str(date_today)]=l2

    exp=[]
    for j in range(sla.shape[0]):
        # if(data1['CVSS'][i]>=sla['SB'][j] and data1['CVSS'][i]<=sla['SE'][j]):
        string_seg=str(sla['SB'][j])+ " - " +str(sla['SE'][j])
        seg1.update({str(string_seg):0})
    for i in range(data1.shape[0]):
        for j in range(sla.shape[0]):
            if(data1['CVSS'][i]>=sla['SB'][j] and data1['CVSS'][i]<=sla['SE'][j]):
    
                string_seg=str(sla['SB'][j])+ " - " +str(sla['SE'][j])
                if string_seg in seg1:
                    seg1[str(string_seg)]+=1
                 #print("DEBUG")
                else:
                    seg1.update({string_seg:1})           
                if(sla['Duration'][j]<data1[str(date_today)][i]):
                    exp.append("Over Due")
                else:
                    
                    exp.append("On Time")
    
    #print(seg1)
    data1["overdue"]=exp
    exp2=[]
    age2=0
    for j in range(sla.shape[0]):
        if(6.8>=sla['SB'][j] and 6.8<=sla['SE'][j]):
            age2=sla['Duration'][j]
    # print("age2= ",age2)
    
    for i in range(data2.shape[0]):
        if(data2[str(date_today)][i]<age2):
            exp2.append("Over Due")
        else:
            exp2.append("On Time")
    data2["overdue"]=exp2
    data1.sort_values(by=str(date_today) ,ascending=False,inplace=True)
    data2.sort_values(by=str(date_today) ,ascending=False,inplace=True)
    
    return render_template('index.html')
    

data3=pd.DataFrame
data4=pd.DataFrame



@app.route('/table')
def table():
    
    data3=data1[['ID','Title','CVSS','Created_date','overdue']]
    # print(data3)
    table1=data3.to_numpy()
    df4=data3['overdue'].value_counts()
    df4=df4.to_dict()
    # print(df4)
    overdue_df1=data1[data1["overdue"]=="Over Due"]
    data3=data3[data3["overdue"]=="On Time"]
    print(seg1)

    return render_template('table.html',tables=data3,df=df4,table_od1=overdue_df1,sd=seg1)
    



@app.route('/table2')
def table2():
    sec={}
    for i in range(occur.shape[0]):
        if(occur['AWS Account'][i] in sec):
            sec[str(occur['AWS Account'][i])][0]+=occur['Security Score'][i]
            sec[str(occur['AWS Account'][i])][1]+=1
        else:
            p=[]
            p.append(occur['Security Score'][i])
            p.append(1)
            sec.update({str(occur['AWS Account'][i]): p})
    sec2={}
    for i in sec:
        sec2.update({i:sec[i][0]/sec[i][1]})
    # print(sec2)

    return render_template('table2.html',scores=sec2)

@app.route('/coverity')
def coverity():
    df1=data2['Team Backlog'].value_counts()
    # print(df1)
    df1=df1.to_dict()
    da1=data2['Dashboard Category'].value_counts()
    da1=da1.to_dict()
    data4=data2[['Dashboard Category','CID','ART','Team Backlog','Severity','Type','Category','CWE','Checker','Action','File','External Reference','Baseline','First Detected','overdue']]
    # print(data4)
    data4=data4.sort_values(by="Dashboard Category")
    table2=data4.to_numpy()
    # print(table2)
    df5=data4['overdue'].value_counts()
    # print(df5)
    df5=df5.to_dict()
    overdue_df2=data4[data4["overdue"]=="Over Due"]
    data4=data4[data4["overdue"]=="On Time"]
    return render_template('coverity.html',df=df1,da=da1,tables=data4,od=df5,table_od2=overdue_df2)
if  __name__=='__main__':
    app.run(debug=True)