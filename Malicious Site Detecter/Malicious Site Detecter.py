import requests
import json
import time
import re
from flask import Flask, request, jsonify
import concurrent.futures
from flask_cors import CORS
import os
import random
import tensorflow as tf
import pandas as pd
import google.generativeai as genai
import json

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Virustotal API kaynakları kulllarak domainin güvenliği hakkında veri elde eden fonksiyon
def scan_domain_virustotal(domain, vt_key, proxy):
    result = json.loads('{}')
    target_result = json.loads('{}')
    
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    
    proxy_list = {
        'http': proxy
    }

    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }
    try:
        response = requests.get(url, headers=headers, proxies= proxy_list)
    except:
        print('1')
        try:
            response = requests.get(url, headers=headers, proxies= proxy_list)
        except:
            time.sleep(3)
            response = requests.get(url, headers=headers, proxies= proxy_list)

    if response.status_code == 200:
        result['result'] = True

        data = response.json()['data']['attributes']

        reputation = data['reputation']
        target_result['reputation'] = reputation


        analysis_stats = data['last_analysis_stats']
        target_result['analysis_stats'] = analysis_stats

        analysis_results = data['last_analysis_results']
        temp_result = {}

        for i in analysis_results:
            analysis_result = analysis_results[i]
            if analysis_result['result'] != 'clean' and analysis_result['result'] != 'unrated':
                temp_result[analysis_result['result']] = []

        for i in analysis_results:
            analysis_result = analysis_results[i]
            if analysis_result['result'] != 'clean' and analysis_result['result'] != 'unrated':
                temp_result[analysis_result['result']].append(analysis_result['engine_name'])
                

        target_result['malicious'] = temp_result
        
        result['detail'] = target_result

    else:
        print(response.text)
        return {'result': False}
    
    return result


# Virustotal API kaynakları kulllarak bir sitenin güvenliği hakkında veri elde eden fonksiyon
def scan_url_virustotal(target_url, vt_key, proxy):
    url = "https://www.virustotal.com/api/v3/urls"

    payload = {"url": target_url}
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    proxy_list = {
        'http': proxy
    }

    try:
        response = requests.post(url, data=payload, headers=headers, proxies= proxy_list)
    except:
        print('2')
        try:
            response = requests.post(url, data=payload, headers=headers, proxies= proxy_list)
        except:
            time.sleep(3)
            response = requests.post(url, data=payload, headers=headers, proxies= proxy_list)

    link = response.json()['data']['links']['self']

    response1 = requests.get(link, headers=headers, proxies= proxy_list)

    result = json.loads('{}')
    target_result = json.loads('{}')
    main_data = response1.json()

    if response1.status_code == 200:
        if main_data['data']['attributes']['status'] == 'queued':
            time.sleep(30)
            response1 = requests.get(link, headers=headers)
        
        result['result'] = True

        data = response1.json()['data']['attributes']

        analysis_results = data['results']
        temp_result = {}
        #print(analysis_results)
        for i in analysis_results:
            analysis_result = analysis_results[i]
            if analysis_result['result'] != 'clean' and analysis_result['result'] != 'unrated':
                temp_result[analysis_result['result']] = []

        for i in analysis_results:
            analysis_result = analysis_results[i]
            if analysis_result['result'] != 'clean' and analysis_result['result'] != 'unrated':
                temp_result[analysis_result['result']].append(analysis_result['engine_name'])
                
        target_result['url_malicious'] = temp_result
        result['detail'] = target_result

        return result

    else:
        print('Finished')
        return {'result': False}

# Virustotal API kaynakları kulllarak bir site hakkında yapılan yorumları toplayan fonksiyon
def comment_virustotal(domain, vt_key, proxy):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/comments?limit=40"

    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }
    proxy_list = {
        'http': proxy
    }

    try:
        response = requests.get(url, headers=headers, proxies= proxy_list)
    except:
        print('3')
        try:
            response = requests.get(url, headers=headers, proxies= proxy_list)
        except:
            time.sleep(3)
            response = requests.get(url, headers=headers, proxies= proxy_list)

    result = json.loads('{}')
    target_result = json.loads('{}')

    if response.status_code == 200:
        result['result'] = True

        data = response.json()

        comment_count = data['meta']['count']
        target_result['comment_count'] = comment_count

        data = data['data']
        temp_text = []
        for i in data:
            attributes = i['attributes']
            temp_text.append(attributes['text'])

        target_result['comments'] = temp_text

        result['detail'] = target_result

    else:
        result['result'] = False

    return result



# CheckPhishAI API kaynakları kulllarak domainin güvenliği hakkında verilerin çekilmesi için iş başlatan fonksiyon
def start_checkphishai(domain, cp_key, proxy):
    url = "https://developers.checkphish.ai/api/neo/scan"

    headers = {
        "accept": "application/json",
    }

    post_data = {
        "apiKey": cp_key,
        "urlInfo": {
            "url": domain
        },
        "scanType": "full"
    }
    proxy_list = {
        'http': proxy
    }
    try:
        response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)
        #print(response.text)
    except:
        print('4')
        try:
            response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)
        except:
            time.sleep(3)
            response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)


    if response.status_code == 200:
        job_id = response.json()['jobID']
        return job_id
    
    else:
        return False

# CheckPhishAI API kaynakları kulllarak domainin güvenliği hakkında başlatan işin verilerini toplayan fonksiyon
def check_checkphishai(job_id, cp_key, proxy):
    result = json.loads('{}')

    url = "https://developers.checkphish.ai/api/neo/scan/status"

    headers = {
        "accept": "application/json",
    }

    post_data = {
        "apiKey": cp_key,
        "jobID": job_id,
        "insights": True
        }
    
    proxy_list = {
        'http': proxy
    }

    try:
        response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)
        #print(response.text)
    except:
        print('5')
        try:
            response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)
        except:
            time.sleep(3)
            response = requests.post(url, headers=headers, json= post_data, proxies= proxy_list)

    if response.status_code == 200:
        result['result'] = True
        data = response.json()
        
        if data['status'] == 'DONE':
            result['disposition'] = data['disposition']
        else:
            time.sleep(12)
            return check_checkphishai(job_id, cp_key, proxy)
        #print(response.json())
    else:
        result['result'] = False
    
    return result

# CheckPhishAI API kaynakları kulllarak domainin güvenliği hakkında işi başlatan ve verileri toplanmasını sağlayan ana fonksiyon
def main_checkphishai(domain, cp_key, proxy):
    job_id = start_checkphishai(domain, cp_key, proxy)
    if job_id:
        if job_id != 'none':
            time.sleep(random.uniform(18,23))
            return check_checkphishai(job_id, cp_key, proxy)
        elif job_id == 'none':
            print(cp_key + 'Banned')


# APIVoid API kaynakları kulllarak domainin güvenliği hakkında veri elde eden fonksiyon
def check_apivoid(domain, api_key, proxy):
    result = json.loads('{}')
    target_result = json.loads('{}')
    
    proxy_list = {
        'http': proxy
    }

    url = f"https://endpoint.apivoid.com/sitetrust/v1/pay-as-you-go/?key={api_key}&host={domain}"

    headers = {
        "accept": "application/json"
    }

    response = requests.get(url, headers=headers, proxies=proxy_list)
    #print(response.json())
    if response.status_code == 200:
        result['result'] = True
        
        data = response.json()['data']['report']

        target_result['domain_age'] = data['domain_age']
        target_result['detections'] = data['domain_blacklist']['detections']

        domain_blacklist = data['domain_blacklist']['engines']
        temp_blacklist = []
        for i in domain_blacklist:
            if i['detected'] == True:
                temp_blacklist.append(i)

        target_result['detected_list'] = temp_blacklist
        
        ecommerce_platform = data['ecommerce_platform']

        target_result['ecommerce_platform'] = ecommerce_platform

        security_checks = data['security_checks']

        target_result['security_checks'] = security_checks

        target_result['trust_score'] = data['trust_score']['result']
        target_result['web_page'] = data['web_page']

        result['detail'] = target_result
    
    else:
        result['result'] = False

    return result

# Taranılan sitenin verilerini sonradan kullanabilmek amaçlı servera kaydeden fonksiyon
def save_data(result):
    file_path = os.path.join(os.getcwd(), 'Malicious Site Detecter Results.json')

    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            existing_data = json.load(f)
    else:
        existing_data = []

    existing_data.append(result)

    with open(file_path, "w") as f:
        json.dump(existing_data, f, indent=4)

# Elde edilen verileri k-NN sınıflandırması için uygun formata getiren fonksiyon
def get_csv_version(data):    
    url_malicious = data['virustotal_url_results']['detail']['url_malicious']
    malicious_entities = []

    for k in url_malicious.values():
        if type(k) == list:
            for a in k:
                malicious_entities.append(a)

    malicious_reason = []
    for k in url_malicious.keys():
        malicious_reason.append(k)

    del data['virustotal_url_results']['detail']['url_malicious']
    data['virustotal_url_results']['detail']['url_malicious'] = malicious_entities
    data['virustotal_url_results']['detail']['url_malicious_reason'] = malicious_reason

    domain_malicious = data['virustotal_domain_results']['detail']['malicious']

    malicious_entities = []
    for k in domain_malicious.values():
        if type(k) == list:
            for a in k:
                malicious_entities.append(a)
        else:
            print(domain_malicious)

    malicious_reason = []
    for k in domain_malicious.keys():
        malicious_reason.append(k)

    del data['virustotal_domain_results']['detail']['malicious']
    data['virustotal_domain_results']['detail']['domain_malicious'] = malicious_entities
    data['virustotal_domain_results']['detail']['domain_malicious_reason'] = malicious_reason

    df = pd.DataFrame({
        'url': [data['url']],
        'domain': [data['domain']],
        'vt_domain_reputation': [data['virustotal_domain_results']['detail']['reputation']],
        'vt_domain_harmless': [data['virustotal_domain_results']['detail']['analysis_stats']['harmless']],
        'vt_domain_malicious': [data['virustotal_domain_results']['detail']['analysis_stats']['malicious']],
        'vt_domain_suspicious': [data['virustotal_domain_results']['detail']['analysis_stats']['suspicious']],
        'vt_domain_undetected': [data['virustotal_domain_results']['detail']['analysis_stats']['undetected']],
        'vt_domain_mal_reason_not_recommended': [int('not_recommended' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_phishing': [int('phishing' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_spam': [int('spam' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_fraud': [int('fraud' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_malware': [int('malware' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_malicious': [int('malicious' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_suspicious': [int('suspicious' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_url_malicious': [int(data['virustotal_url_results']['result'])],
        'vt_url_mal_reason_not_recommended': [int('not_recommended' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_phishing': [int('phishing' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_spam': [int('spam' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_fraud': [int('fraud' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_malware': [int('malware' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_malicious': [int('malicious' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_suspicious': [int('suspicious' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'cpai_disposition_clean': [int(data['checkphishai_results']['disposition'] == 'clean')],
        'cpai_disposition_scam': [int(data['checkphishai_results']['disposition'] == 'scam')],
        'cpai_disposition_suspicious': [int(data['checkphishai_results']['disposition'] == 'suspicious')],
        'cpai_disposition_phish': [int(data['checkphishai_results']['disposition'] == 'phish')],
    })
    return df

# Elde edilen verileri Gemini için uygun formata getiren fonksiyon
def get_csv_version_for_gemini(data):
    df = pd.DataFrame({
        'url': [data['url']],
        'domain': [data['domain']],
        'vt_domain_reputation': [data['virustotal_domain_results']['detail']['reputation']],
        'vt_domain_harmless': [data['virustotal_domain_results']['detail']['analysis_stats']['harmless']],
        'vt_domain_malicious': [data['virustotal_domain_results']['detail']['analysis_stats']['malicious']],
        'vt_domain_suspicious': [data['virustotal_domain_results']['detail']['analysis_stats']['suspicious']],
        'vt_domain_undetected': [data['virustotal_domain_results']['detail']['analysis_stats']['undetected']],
        'vt_domain_detailed_malicious': [str(data['virustotal_domain_results']['detail']['domain_malicious'])],
        'vt_domain_mal_reason_not_recommended': [int('not_recommended' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_phishing': [int('phishing' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_spam': [int('spam' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_fraud': [int('fraud' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_malware': [int('malware' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_malicious': [int('malicious' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_domain_mal_reason_suspicious': [int('suspicious' in data['virustotal_domain_results']['detail']['domain_malicious_reason'])],
        'vt_url_malicious': [int(data['virustotal_url_results']['result'])],
        'vt_url_detailed_malicious': [str(data['virustotal_url_results']['detail']['url_malicious'])],
        'vt_url_mal_reason_not_recommended': [int('not_recommended' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_phishing': [int('phishing' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_spam': [int('spam' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_fraud': [int('fraud' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_malware': [int('malware' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_malicious': [int('malicious' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'vt_url_mal_reason_suspicious': [int('suspicious' in data['virustotal_url_results']['detail']['url_malicious_reason'])],
        'cpai_disposition_clean': [int(data['checkphishai_results']['disposition'] == 'clean')],
        'cpai_disposition_scam': [int(data['checkphishai_results']['disposition'] == 'scam')],
        'cpai_disposition_suspicious': [int(data['checkphishai_results']['disposition'] == 'suspicious')],
        'cpai_disposition_phish': [int(data['checkphishai_results']['disposition'] == 'phish')],
        'virustotal_comments_result': [data['virustotal_comments']['result']],
        'virustotal_comments_comment_count': [data['virustotal_comments']['detail']['comment_count']],
        'virustotal_comments_comments': [data['virustotal_comments']['detail']['comments']],
        'apivoid_results_result': [data['apivoid_results']['result']],
        'apivoid_results_domain_age_found': [data['apivoid_results']['detail']['domain_age']['found']],
        'apivoid_results_domain_age_creation_date': [data['apivoid_results']['detail']['domain_age']['domain_creation_date']],
        'apivoid_results_domain_age_in_days': [data['apivoid_results']['detail']['domain_age']['domain_age_in_days']],
        'apivoid_results_domain_age_in_months': [data['apivoid_results']['detail']['domain_age']['domain_age_in_months']],
        'apivoid_results_domain_age_in_years': [data['apivoid_results']['detail']['domain_age']['domain_age_in_years']],
        'apivoid_results_detections': [data['apivoid_results']['detail']['detections']],
        'apivoid_results_detected_list': [[item['name'] for item in data['apivoid_results']['detail']['detected_list']]],
        'apivoid_results_ecommerce_platform_is_shopify': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_shopify'])],
        'apivoid_results_ecommerce_platform_is_woocommerce': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_woocommerce'])],
        'apivoid_results_ecommerce_platform_is_opencart': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_opencart'])],
        'apivoid_results_ecommerce_platform_is_prestashop': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_prestashop'])],
        'apivoid_results_ecommerce_platform_is_magento': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_magento'])],
        'apivoid_results_ecommerce_platform_is_zencart': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_zencart'])],
        'apivoid_results_ecommerce_platform_is_shoplazza': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_shoplazza'])],
        'apivoid_results_ecommerce_platform_is_shopyy': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_shopyy'])],
        'apivoid_results_ecommerce_platform_is_youcanshop': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_youcanshop'])],
        'apivoid_results_ecommerce_platform_is_ueeshop': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_ueeshop'])],
        'apivoid_results_ecommerce_platform_is_other': [int(data['apivoid_results']['detail']['ecommerce_platform']['is_other'])],
        'apivoid_results_security_checks_is_suspended_site': [int(data['apivoid_results']['detail']['security_checks']['is_suspended_site'])],
        'apivoid_results_security_checks_is_most_abused_tld': [int(data['apivoid_results']['detail']['security_checks']['is_most_abused_tld'])],
        'apivoid_results_security_checks_is_robots_noindex': [int(data['apivoid_results']['detail']['security_checks']['is_robots_noindex'])],
        'apivoid_results_security_checks_is_website_accessible': [int(data['apivoid_results']['detail']['security_checks']['is_website_accessible'])],
        'apivoid_results_security_checks_is_empty_page_content': [int(data['apivoid_results']['detail']['security_checks']['is_empty_page_content'])],
        'apivoid_results_security_checks_is_redirect_to_search_engine': [int(data['apivoid_results']['detail']['security_checks']['is_redirect_to_search_engine'])],
        'apivoid_results_trust_score': [data['apivoid_results']['detail']['trust_score']],
        'apivoid_results_web_page_title': [data['apivoid_results']['detail']['web_page']['title']],
        'apivoid_results_web_page_description': [data['apivoid_results']['detail']['web_page']['description']],
        'apivoid_results_web_page_keywords': [data['apivoid_results']['detail']['web_page']['keywords']],
        'knn_result': [data['knn_result']]
    })
    df_data = ','.join(df.iloc[0].astype(str))
    return df_data


# Elde edilen verileri k-NN sınıflandırması ile k-NN değerini hesaplayan fonksiyon
def get_knn_result(df):
    path = os.path.join(os.getcwd(), 'num_model.h5')

    # Önceden eğitilmiş TensorFlow modelini yükle
    model = tf.keras.models.load_model(
        path, 
        custom_objects=None, 
        compile=True, 
        options=None
    )
    predictions = [] # Tahmin sonuçlarını depolamak için bir liste

    # Veri çerçevesinin her satırı için oluşturulan döngü
    for index, row in df.iterrows():
        values = [
            float(row['vt_domain_reputation']),
            float(row['vt_domain_harmless']),
            float(row['vt_domain_malicious']),
            float(row['vt_domain_suspicious']),
            float(row['vt_domain_undetected']),
            float(row['vt_domain_mal_reason_not_recommended']),
            float(row['vt_domain_mal_reason_phishing']),
            float(row['vt_domain_mal_reason_spam']),
            float(row['vt_domain_mal_reason_fraud']),
            float(row['vt_domain_mal_reason_malware']),
            float(row['vt_domain_mal_reason_malicious']),
            float(row['vt_domain_mal_reason_suspicious']),
            float(row['vt_url_malicious']),
            float(row['vt_url_mal_reason_not_recommended']),
            float(row['vt_url_mal_reason_phishing']),
            float(row['vt_url_mal_reason_spam']),
            float(row['vt_url_mal_reason_fraud']),
            float(row['vt_url_mal_reason_malware']),
            float(row['vt_url_mal_reason_malicious']),
            float(row['vt_url_mal_reason_suspicious']),
            float(row['cpai_disposition_clean']),
            float(row['cpai_disposition_scam']),
            float(row['cpai_disposition_suspicious']),
            float(row['cpai_disposition_phish'])
        ]

        # Giriş tensörünü oluşturularak ve modeli kullanarak tahmin yapılıyor
        inputTensor = tf.expand_dims(values, 0)
        predictValue = model.predict(inputTensor, verbose=2)[0][0]

        # Tahmin değeri listeye eklenir
        predictions.append(predictValue)

    # Tahminleri veri çerçevesine eklenir
    df['knn_result'] = predictions

    # Yeni bir CSV dosyasına kaydedin
    # new_csv_file_path = r'temp_csv_data_with_prediction.csv'
    # df.to_csv(new_csv_file_path, index=False)

    # Tahminleri döndürün
    return predictions


# Tüm verilerin Gemini ortamında Güvenilirlik Yüzdesinin hesaplanmasını sağlayan fonksiyon
def get_gemini_result(data, ge_key):

    genai.configure(api_key=ge_key)

    # Gemini'nin yanıt verme ayarları yapılır.
    generation_config = {
    "temperature": 0.9,
    "top_p": 1,
    "top_k": 1,
    "max_output_tokens": 2048,
    }
    # Gemini'nin güvenilirlik ayarları yapılır.
    safety_settings = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    ]

    # Gemini'ye model ve ayarlar yüklenir.
    model = genai.GenerativeModel(model_name="gemini-pro",
                                generation_config=generation_config,
                                safety_settings=safety_settings)
    
    # Önceden oluşturulmuş prompt yüklenir.
    prompt_parts = [
        f"url,domain,vt_domain_reputation,vt_domain_harmless,vt_domain_malicious,vt_domain_suspicious,vt_domain_undetected,vt_domain_detailed_malicious,vt_domain_mal_reason_not_recommended,vt_domain_mal_reason_phishing,vt_domain_mal_reason_spam,vt_domain_mal_reason_fraud,vt_domain_mal_reason_malware,vt_domain_mal_reason_malicious,vt_domain_mal_reason_suspicious,vt_url_malicious,vt_url_detailed_malicious,vt_url_mal_reason_not_recommended,vt_url_mal_reason_phishing,vt_url_mal_reason_spam,vt_url_mal_reason_fraud,vt_url_mal_reason_malware,vt_url_mal_reason_malicious,vt_url_mal_reason_suspicious,cpai_disposition_clean,cpai_disposition_scam,cpai_disposition_suspicious,cpai_disposition_phish,virustotal_comments_result,virustotal_comments_comment_count,virustotal_comments_comments,apivoid_results_result,apivoid_results_domain_age_found,apivoid_results_domain_age_creation_date,apivoid_results_domain_age_in_days,apivoid_results_domain_age_in_months,apivoid_results_domain_age_in_years,apivoid_results_detections,apivoid_results_detected_list,apivoid_results_ecommerce_platform_is_shopify,apivoid_results_ecommerce_platform_is_woocommerce,apivoid_results_ecommerce_platform_is_opencart,apivoid_results_ecommerce_platform_is_prestashop,apivoid_results_ecommerce_platform_is_magento,apivoid_results_ecommerce_platform_is_zencart,apivoid_results_ecommerce_platform_is_shoplazza,apivoid_results_ecommerce_platform_is_shopyy,apivoid_results_ecommerce_platform_is_youcanshop,apivoid_results_ecommerce_platform_is_ueeshop,apivoid_results_ecommerce_platform_is_other,apivoid_results_security_checks_is_suspended_site,apivoid_results_security_checks_is_most_abused_tld,apivoid_results_security_checks_is_robots_noindex,apivoid_results_security_checks_is_website_accessible,apivoid_results_security_checks_is_empty_page_content,apivoid_results_security_checks_is_redirect_to_search_engine,apivoid_results_trust_score,apivoid_results_web_page_title,apivoid_results_web_page_description,apivoid_results_web_page_keywords,knn_result,is_safe\nhttp://mzukatip.com/,mzukatip.com,0,56,11,0,21,\"['Sophos', 'Avira', 'BitDefender', 'G-Data', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Antiy-AVL', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,1,1,0,11,\"['Sophos', 'Avira', 'BitDefender', 'G-Data', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Antiy-AVL', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,-0.0045869052,True\nhttp://www.mediatrans.md/,mediatrans.md,0,59,10,0,19,\"['CRDF', 'Lionic', 'CyRadar', 'Netcraft', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data']\",0,1,0,0,0,1,0,10,\"['CRDF', 'Lionic', 'CyRadar', 'Netcraft', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2011-12-21,4400,141,12,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,,,,-0.005602747,True\nhttp://polrac.com/,polrac.com,0,56,11,0,21,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CRDF', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,11,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CRDF', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2023-06-29,192,6,0,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,-0.006778449,True\nhttp://www.aebachakon.com/,aebachakon.com,0,57,11,0,20,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Seclookup', 'CyRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,1,1,0,11,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Seclookup', 'CyRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,-0.0070732236,True\nhttp://www.heights.co.kr/,heights.co.kr,0,62,6,1,19,\"['CRDF', 'alphaMountain.ai', 'Seclookup', 'Xcitium Verdict Cloud', 'CyRadar', 'SOCRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,0,1,1,7,\"['CRDF', 'alphaMountain.ai', 'Seclookup', 'Xcitium Verdict Cloud', 'CyRadar', 'SOCRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2018-11-15,1879,60,5,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,중앙산업(주),다른 워드프레스 사이트,,-0.007828653,True\nhttps://becomeawordpressguru.com/,becomeawordpressguru.com,0,57,11,0,20,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,11,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2011-12-28,4393,141,12,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,1,0,0,1,0,0,0,Account Suspended,,,-0.009320855,True\nhttp://bogdanstepien.com/,bogdanstepien.com,0,62,7,1,18,\"['CRDF', 'Seclookup', 'CyRadar', 'alphaMountain.ai', 'Xcitium Verdict Cloud', 'SOCRadar', 'Avira', 'VIPRE']\",0,1,0,0,1,1,1,8,\"['CRDF', 'Seclookup', 'CyRadar', 'alphaMountain.ai', 'Xcitium Verdict Cloud', 'SOCRadar', 'Avira', 'VIPRE']\",0,1,0,0,1,1,1,1,0,0,0,True,0,[],True,True,2014-07-04,3474,112,9,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Bogdan Stepien,,,-0.0096696615,True\nhttp://mail.spotonroofing.com.au/,mail.spotonroofing.com.au,0,55,12,0,21,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,12,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,This is the default server vhost,,,-0.014313817,True\nhttp://tykingministries.org/,tykingministries.org,0,56,12,0,20,\"['Sophos', 'Fortinet', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'CRDF', 'Seclookup', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,12,\"['Sophos', 'Fortinet', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'CRDF', 'Seclookup', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2012-10-16,4100,132,11,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,-0.017068744,True\nhttps://beyondbrewing.co/,beyondbrewing.co,0,57,12,0,19,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,12,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2020-02-13,1424,45,3,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,70,,,,-0.01981476,True\nhttp://vaportwist.co.uk/,vaportwist.co.uk,0,58,12,0,18,\"['Sophos', 'alphaMountain.ai', 'Lionic', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'Xcitium Verdict Cloud', 'CyRadar', 'Antiy-AVL', 'Avira', 'VIPRE']\",0,1,0,0,1,1,0,12,\"['Sophos', 'alphaMountain.ai', 'Lionic', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'Xcitium Verdict Cloud', 'CyRadar', 'Antiy-AVL', 'Avira', 'VIPRE']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,-0.020274699,True\nhttps://canelovsjacobsfight.com/,canelovsjacobsfight.com,0,54,14,0,20,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'CyRadar', 'Webroot', 'Antiy-AVL', 'Bfore.Ai PreCrime']\",0,1,0,0,0,1,0,14,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'Forcepoint ThreatSeeker', 'CyRadar', 'Webroot', 'Antiy-AVL', 'Bfore.Ai PreCrime']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,-0.035464495,True\nhttps://natturi.com/,natturi.com,0,54,15,0,19,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'VIPRE', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,15,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'VIPRE', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2023-06-30,191,6,0,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,,,,-0.047348768,True\nhttp://lockdl.cf/,lockdl.cf,0,55,15,0,18,\"['Sophos', 'Fortinet', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'VIPRE', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,15,\"['Sophos', 'Fortinet', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Kaspersky', 'SOCRadar', 'BitDefender', 'G-Data', 'VIPRE', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,1,0,35,,,,-0.050201505,True\nhttps://gestmsmions.firebaseapp.com/,gestmsmions.firebaseapp.com,0,59,9,0,20,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Forcepoint ThreatSeeker', 'ESET', 'CyRadar']\",0,1,0,0,0,1,0,9,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'Forcepoint ThreatSeeker', 'ESET', 'CyRadar']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2012-10-15,4101,132,11,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Site Not Found,,,0.00012788177,True\nhttps://zonascgurabeta-viabcp.com/,zonascgurabeta-viabcp.com,0,60,8,0,20,\"['Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot']\",0,1,0,0,0,1,0,8,\"['Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.00280115,True\nhttp://averawebservices.in/,averawebservices.in,0,60,8,0,20,\"['Lionic', 'Seclookup', 'CyRadar', 'Antiy-AVL', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,0,1,0,8,\"['Lionic', 'Seclookup', 'CyRadar', 'Antiy-AVL', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.00280115,True\nhttp://rayaviation.com/,rayaviation.com,0,64,3,1,20,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,4,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2018-11-20,1874,60,5,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Ray Aviation | The Ultimate Travel Soluton,,,0.008212417,True\nhttps://wycca.com/,wycca.com,0,64,3,1,20,\"['alphaMountain.ai', 'Xcitium Verdict Cloud', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,4,\"['alphaMountain.ai', 'Xcitium Verdict Cloud', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2018-02-22,2145,69,5,1,['CRDF'],0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Storage Calculator for Storage Facility | What Your Customer Can Afford,\"Discover what your customers can afford with self storage analytics software. Our handy calculator takes the guess work out of setting prices for your self storage facility, providing instant results.\",,0.008212417,True\nhttp://www.guidos-restaurants.de/,guidos-restaurants.de,0,62,6,0,20,\"['alphaMountain.ai', 'SOCRadar', 'BitDefender', 'G-Data', 'Seclookup', 'CyRadar']\",0,1,0,0,0,1,0,6,\"['alphaMountain.ai', 'SOCRadar', 'BitDefender', 'G-Data', 'Seclookup', 'CyRadar']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,0.00856629,True\nhttp://u0803923.cp.regruhosting.ru/,u0803923.cp.regruhosting.ru,0,59,8,0,21,\"['Sophos', 'Lionic', 'Avira', 'BitDefender', 'G-Data', 'CyRadar', 'Netcraft', 'Emsisoft']\",0,1,0,0,1,1,0,8,\"['Sophos', 'Lionic', 'Avira', 'BitDefender', 'G-Data', 'CyRadar', 'Netcraft', 'Emsisoft']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2008-04-17,5743,185,15,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.008690566,True\nhttps://www.apapayl.com/,apapayl.com,0,59,8,0,21,\"['alphaMountain.ai', 'SOCRadar', 'Lionic', 'Seclookup', 'Xcitium Verdict Cloud', 'CyRadar', 'Webroot', 'Avira']\",0,1,0,0,1,1,0,8,\"['alphaMountain.ai', 'SOCRadar', 'Lionic', 'Seclookup', 'Xcitium Verdict Cloud', 'CyRadar', 'Webroot', 'Avira']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.008690566,True\nhttps://ptkwatch.com/,ptkwatch.com,0,63,6,0,19,\"['CRDF', 'CyRadar', 'Webroot', 'alphaMountain.ai', 'SOCRadar', 'Xcitium Verdict Cloud']\",0,1,0,0,1,1,0,6,\"['CRDF', 'CyRadar', 'Webroot', 'alphaMountain.ai', 'SOCRadar', 'Xcitium Verdict Cloud']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2023-07-13,178,5,0,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,0.009978801,True\nhttp://www.kiri.com.au/,kiri.com.au,0,62,3,1,22,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,4,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,60,,,,0.013122439,True\nhttp://www.z7z.org/,z7z.org,0,63,5,0,20,\"['Fortinet', 'Xcitium Verdict Cloud', 'SOCRadar', 'CyRadar', 'Webroot']\",0,1,0,0,0,1,0,5,\"['Fortinet', 'Xcitium Verdict Cloud', 'SOCRadar', 'CyRadar', 'Webroot']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2003-05-15,7542,243,20,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Apache2 Debian Default Page: It works,,,0.013769031,True\nhttps://mail.nonaturma.com.br/,mail.nonaturma.com.br,0,61,6,0,21,\"['Fortinet', 'Xcitium Verdict Cloud', 'SOCRadar', 'Seclookup', 'CyRadar', 'Avira']\",0,1,0,0,1,1,0,6,\"['Fortinet', 'Xcitium Verdict Cloud', 'SOCRadar', 'Seclookup', 'CyRadar', 'Avira']\",0,1,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2008-10-08,5569,179,15,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.014728069,True\nhttp://www.cogentdatasolutions.com/,cogentdatasolutions.com,0,66,2,1,19,\"['alphaMountain.ai', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,3,\"['alphaMountain.ai', 'CyRadar', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2007-09-14,5959,192,16,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,Cogent Data Solutions LLC,Passionate People Powerful Results,,0.015758425,True\nhttp://www.bellyncketfils.fr/,bellyncketfils.fr,0,65,2,1,20,\"['CRDF', 'alphaMountain.ai', 'SOCRadar']\",0,1,0,0,0,1,1,3,\"['CRDF', 'alphaMountain.ai', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2009-05-06,5359,172,14,1,['CRDF'],0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Equipement culinaire et de la cuisine,,\"materiel,cuisine,culinaire,equipement,ustensile,appareil,electromenager\",0.017985493,True\nhttps://cababox.com/,cababox.com,0,64,4,0,20,\"['CRDF', 'Seclookup', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,4,\"['CRDF', 'Seclookup', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2022-10-27,437,14,1,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.020428866,True\nhttp://emailconfirmupdate.moonfruit.com/,emailconfirmupdate.moonfruit.com,0,62,2,0,24,\"['Fortinet', 'Antiy-AVL']\",0,1,0,0,0,1,0,2,\"['Fortinet', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2023-11-30,38,1,0,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,10,,,,0.056527644,True\nhttp://guihangdimyhcm.com/,guihangdimyhcm.com,0,66,3,0,19,\"['Xcitium Verdict Cloud', 'SOCRadar', 'ESET']\",0,1,0,0,0,0,0,3,\"['Xcitium Verdict Cloud', 'SOCRadar', 'ESET']\",0,1,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2016-12-29,2565,82,7,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.08237627,True\nhttp://telegram-downloads.ru/,telegram-downloads.ru,0,67,2,0,19,\"['Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,0,0,2,\"['Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2015-09-29,3022,97,8,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Мессенджер Телеграмм на русском,\"Telegram мессенджер от Павла Дурова - это модный, безопасный и мультиплатформенный мессенджер, созданный для обмена короткими сообщениями и медиафайлами.\",\"telegram мессенджер от павла дурова,telegram приложение,мессенджер телеграмм на русском,телеграмм мессенджер скачать,telegram messenger на русском,как русифицировать телеграмм,телеграмм,telegram\",0.104359925,True\nhttp://viking.comtecint.dk/,viking.comtecint.dk,0,67,2,0,19,\"['Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,0,0,2,\"['Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2004-01-29,7283,234,19,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,Her flytter snart en ny kunde ind | Powerhosting - Service du kan regne med,Powerhosting leverer kvalitetswebhosting til kræsne virksomheder og private • Hurtig og kompetent kundeservice • Hosting med telefonsupport,,0.104359925,True\nhttp://lm.facebook.com.https.s1.gvirabi.com/,lm.facebook.com.https.s1.gvirabi.com,0,60,7,0,21,\"['Sophos', 'Fortinet', 'Avira', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,7,\"['Sophos', 'Fortinet', 'Avira', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,0,0,1,0,True,0,[],True,True,2020-09-01,1223,39,3,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.23307692,True\nhttp://xtremefish.rs/,xtremefish.rs,-45,58,10,0,20,\"['Sophos', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,10,\"['Sophos', 'Lionic', 'Xcitium Verdict Cloud', 'Avira', 'SOCRadar', 'Forcepoint ThreatSeeker', 'Seclookup', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,1,['RuneScape phishing community.'],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.24612775,True\nhttps://sdftyujklvbn.blogspot.com/,sdftyujklvbn.blogspot.com,0,57,10,0,21,\"['Sophos', 'Fortinet', 'Lionic', 'Avira', 'BitDefender', 'G-Data', 'alphaMountain.ai', 'CyRadar', 'Dr.Web', 'Webroot']\",0,0,0,0,1,1,0,10,\"['Sophos', 'Fortinet', 'Lionic', 'Avira', 'BitDefender', 'G-Data', 'alphaMountain.ai', 'CyRadar', 'Dr.Web', 'Webroot']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2000-07-31,8560,276,23,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Blog not found,\"Blogger is a blog publishing tool from Google for easily sharing your thoughts with the world. Blogger makes it simple to post text, photos and video onto your personal or team blog.\",\"blogger, blogspot, blog, blogger.com, blogspot.com, personal blog, weblog, create blog, new blog\",0.24642964,True\nhttps://investmentbank.barclays.com.admin-us.cas.ms/,investmentbank.barclays.com.admin-us.cas.ms,0,63,4,0,21,\"['CRDF', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,0,0,0,0,1,0,4,\"['CRDF', 'CyRadar', 'Webroot', 'Antiy-AVL']\",0,0,0,0,0,1,0,0,0,1,0,True,0,[],True,True,2016-01-18,2911,93,7,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.2548474,True\nhttp://po.do/,po.do,-41,64,4,1,19,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,1,5,\"['alphaMountain.ai', 'Seclookup', 'CyRadar', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2023-11-01,67,2,0,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,10,,,,0.2583389,True\nhttp://paypal-comn.byethost24.com/,paypal-comn.byethost24.com,0,65,1,1,21,\"['alphaMountain.ai', 'Webroot']\",0,0,0,0,0,1,1,2,\"['alphaMountain.ai', 'Webroot']\",0,0,0,0,0,1,1,0,0,1,0,True,0,[],True,True,2005-10-03,6670,215,18,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.26052547,True\nhttps://coinbasepro10000.webcindario.com/,coinbasepro10000.webcindario.com,0,65,1,1,21,\"['CyRadar', 'ESET']\",0,0,0,0,0,1,1,2,\"['CyRadar', 'ESET']\",0,0,0,0,0,1,1,0,0,1,0,True,0,[],True,True,2001-02-28,8348,269,22,2,\"['EtherScamDB', 'EtherAddressLookup']\",0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,,,,0.26052547,True\nhttps://paypal.co.uk.4n94.icu/,paypal.co.uk.4n94.icu,0,62,2,2,22,\"['alphaMountain.ai', 'Forcepoint ThreatSeeker', 'CyRadar', 'Webroot']\",0,0,0,0,0,1,1,4,\"['alphaMountain.ai', 'Forcepoint ThreatSeeker', 'CyRadar', 'Webroot']\",0,0,0,0,0,1,1,0,0,1,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,1,0,35,,,,0.26137066,True\nhttps://impots.remboursements.gbfgbf.nity.fr/,impots.remboursements.gbfgbf.nity.fr,0,65,3,0,20,\"['Xcitium Verdict Cloud', 'CyRadar', 'Webroot']\",0,0,0,0,0,1,0,3,\"['Xcitium Verdict Cloud', 'CyRadar', 'Webroot']\",0,0,0,0,0,1,0,0,0,1,0,True,0,[],True,True,2018-10-12,1913,61,5,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Web Server's Default Page,,,0.2634726,True\nhttps://speakspurink.com/,speakspurink.com,0,60,8,0,20,\"['CRDF', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Dr.Web', 'Bfore.Ai PreCrime', 'ESET']\",0,0,0,0,1,1,0,8,\"['CRDF', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Dr.Web', 'Bfore.Ai PreCrime', 'ESET']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2022-12-24,379,12,1,1,['Suspicious Hosting IP'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,301 Moved Permanently,,,0.27297238,False\nhttps://sweepfrequencydissolved.com/,sweepfrequencydissolved.com,0,59,8,0,21,\"['CRDF', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Dr.Web', 'Bfore.Ai PreCrime', 'ESET']\",0,0,0,0,1,1,0,8,\"['CRDF', 'alphaMountain.ai', 'Lionic', 'Seclookup', 'CyRadar', 'Dr.Web', 'Bfore.Ai PreCrime', 'ESET']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2023-01-22,350,11,0,2,\"['CRDF', 'Suspicious Hosting IP']\",0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,301 Moved Permanently,,,0.27410072,False\nhttp://albel.intnet.mu/,albel.intnet.mu,0,63,4,0,21,\"['CRDF', 'alphaMountain.ai', 'Dr.Web', 'Webroot']\",0,0,0,0,0,1,0,4,\"['CRDF', 'alphaMountain.ai', 'Dr.Web', 'Webroot']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,1996-02-19,10184,328,27,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,0.33328512,True\nhttps://www.aproveiteodesconto.com/,aproveiteodesconto.com,0,60,4,0,24,\"['Sophos', 'alphaMountain.ai', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,4,\"['Sophos', 'alphaMountain.ai', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2023-11-29,39,1,0,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,35,aproveite o desconto,,,0.33565354,True\nhttps://www378.surpreenda-quem-voce-ama.com/,www378.surpreenda-quem-voce-ama.com,0,61,4,0,23,\"['Sophos', 'alphaMountain.ai', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,4,\"['Sophos', 'alphaMountain.ai', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.3359809,True\nhttp://a0339263.xsph.ru/,a0339263.xsph.ru,0,61,4,0,23,\"['Seclookup', 'CyRadar', 'Avira', 'ESET']\",0,0,0,0,1,1,0,4,\"['Seclookup', 'CyRadar', 'Avira', 'ESET']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2008-07-30,5639,181,15,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,400 Bad Request,,,0.3359809,True\nhttps://s.to/,s.to,0,64,3,0,21,\"['CyRadar', 'Avira', 'SCUMWARE.org']\",0,0,0,0,1,1,0,3,\"['CyRadar', 'Avira', 'SCUMWARE.org']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Home | ❤ S.to - Serien Online gratis ansehen & streamen,\"Bei uns kannst du dir über 5000+ Serien & Animes kostenlos online auf dem Computer, iPhone, iPad, Handy usw. anschauen! ✓ 100% Kostenlos ✓ Sofort ✓ 200.000+ Nutzer\",\"S.to, serien stream, online stream, netflix, Anime4You, Animes, serien kostenlos, serien gratis, disney plus, amazon video, serien deutsch, anime kostenlos, serienstream.to, serienstream, serien gratis, kino, stream, maxdome kostenlos, netflix kostenlos, kinox.to, Android Stream, kinox.to alternative, movie2k, iPad Stream, movie4k, burning series, bs to, burning-seri.es, iphone stream, burning series app, burning series down, mobile stream, burning series serien, Onlineserien\",0.40214497,False\nhttps://apps.esma-edu.com/,apps.esma-edu.com,0,64,3,0,21,\"['Fortinet', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,3,\"['Fortinet', 'Seclookup', 'CyRadar']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2005-09-13,6690,215,18,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,100,,,,0.40214497,True\nhttps://emptivetss.space/,emptivetss.space,0,63,1,1,23,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,1,2,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2022-12-17,386,12,1,0,[],0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,50,,,,0.40328455,False\nhttp://www.aafashiongallery.com/,aafashiongallery.com,0,64,1,1,22,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,1,2,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,1,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.41294304,True\nhttp://www.aaz13.com/,aaz13.com,0,66,1,1,20,\"['alphaMountain.ai', 'Xcitium Verdict Cloud']\",0,0,0,0,0,1,1,2,\"['alphaMountain.ai', 'Xcitium Verdict Cloud']\",0,0,0,0,0,1,1,1,0,0,0,True,0,[],True,True,2015-02-08,3255,105,8,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.45395416,True\nhttps://rclone.org/,rclone.org,0,66,1,2,19,\"['ArcSight Threat Intelligence', 'URLQuery', 'CRDF']\",0,0,0,0,0,1,1,3,\"['ArcSight Threat Intelligence', 'URLQuery', 'CRDF']\",0,0,0,0,0,1,1,1,0,0,0,True,1,\"[\"\"This indicator was mentioned in a report.\\n\\n🔎 Title: Threat Actors Exploit Atlassian Confluence CVE-2023-22515 for Initial Access to Networks\\n📑 Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-289a\\n📆 Report Publish Date: 2023-10-16\\n🏷️ Reference ID: #a48279260 (https://www.virustotal.com/gui/search/a48279260/comments for report's related indicators)\\n\"\"]\",True,True,2013-02-06,3987,128,10,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Rclone,\"Rclone syncs your files to cloud storage: Google Drive, S3, Swift, Dropbox, Google Cloud Storage, Azure, Box and many more.\",,0.4616672,False\nhttps://logsignon22.webcindario.com/,logsignon22.webcindario.com,0,62,2,0,24,\"['Seclookup', 'Webroot']\",0,0,0,0,0,1,0,2,\"['Seclookup', 'Webroot']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2001-02-28,8348,269,22,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.4680498,True\nhttps://tawla.or.tz/,tawla.or.tz,0,65,2,0,21,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,0,2,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2009-07-27,5277,170,14,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Home - TAWLA | Tanzania Women Lawyers Association,\"We are dedicated to the ideal of lifelong learning for women through the advocacy of civil rights, social justice, transparency, integrity, respect, gender equity, good governance and accountability\",,0.510406,True\nhttp://www.shoutmefit.cu.ma/,shoutmefit.cu.ma,0,65,2,0,21,\"['CyRadar', 'Webroot']\",0,0,0,0,0,1,0,2,\"['CyRadar', 'Webroot']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2015-03-19,3216,103,8,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.510406,True\nhttps://www.lyconet.com/,lyconet.com,0,65,2,0,21,\"['Seclookup', 'VIPRE']\",0,0,0,0,0,1,0,2,\"['Seclookup', 'VIPRE']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2013-05-29,3875,125,10,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Lyconet,,,0.510406,False\nhttps://bioguard.com.au/,bioguard.com.au,0,65,2,0,21,\"['Quttera', 'Netcraft']\",0,0,0,0,0,1,0,2,\"['Quttera', 'Netcraft']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,70,BioGuard AUS & NZ | Spa & Pool Chemicals and Equipment,\"BioGuard has been providing Pool & Spa care for over 30 years - pool chemicals, pumps, filters and much more! Find your nearest store here.\",,0.510406,False\nhttps://www.webhostingbingo.com/,webhostingbingo.com,0,65,2,0,21,\"['Seclookup', 'CyRadar']\",0,0,0,0,0,1,0,2,\"['Seclookup', 'CyRadar']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2011-10-08,4474,144,12,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Best Web Hosting in India | Web Hosting Services,\"Best Web Hosting in India! Webhostingbingo offers blazing-fast hosting, free SSL, and expert support. India's web hosting services and meet your online success!\",\"Best Web Hosting in India, Web Hosting Services, Web host\",0.510406,True\nhttps://animepisode.com/,animepisode.com,0,65,2,0,21,\"['Quttera', 'Seclookup']\",0,0,0,0,0,1,0,2,\"['Quttera', 'Seclookup']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2019-06-01,1681,54,4,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,65,,,,0.510406,False\nhttps://maike86888.top/,maike86888.top,0,65,2,0,21,\"['CRDF', 'Avira']\",0,0,0,0,1,1,0,2,\"['CRDF', 'Avira']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2022-05-14,603,19,1,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,发现 -,,,0.51788926,False\nhttps://novogmail2016.webcindario.com/,novogmail2016.webcindario.com,0,65,2,0,21,\"['CyRadar', 'SCUMWARE.org']\",0,0,0,0,1,1,0,2,\"['CyRadar', 'SCUMWARE.org']\",0,0,0,0,1,1,0,1,0,0,0,True,0,[],True,True,2001-02-28,8348,269,22,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.51788926,True\nhttps://www.whonix.org/,whonix.org,0,66,2,0,20,\"['CRDF', 'Seclookup']\",0,0,0,0,0,1,0,2,\"['CRDF', 'Seclookup']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2013-06-14,3859,124,10,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Whonix - Superior Internet Privacy,\"Whonix® can anonymize everything you do online! It runs like an App, is a Free, Open Source and Kicksecure™ hardened Linux distribution.\",,0.53535616,False\nhttps://voe.sx/,voe.sx,0,66,2,0,20,\"['CRDF', 'Seclookup']\",0,0,0,0,0,1,0,2,\"['CRDF', 'Seclookup']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,VOE | Content Delivery Network (CDN) & Video Cloud,\"Host, share, and watch private videos with VOE, the video hosting provider. Join now for easy, reliable video hosting and sharing.\",\"Home, VOE, Video Hosting, Share, Watch, Easy, Reliable, Provider\",0.53535616,False\nhttps://www.ijmuk.org/,ijmuk.org,0,66,2,0,20,\"['Seclookup', 'CyRadar']\",0,0,0,0,0,1,0,2,\"['Seclookup', 'CyRadar']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2003-12-29,7314,235,20,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,Just a moment...,,,0.53535616,True\nhttp://sumsungfime.byethost4.com/,sumsungfime.byethost4.com,0,66,2,0,20,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,0,2,\"['alphaMountain.ai', 'Seclookup']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2005-12-02,6610,213,18,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.53535616,True\nhttp://www.filosofico.net/,filosofico.net,0,66,2,0,20,\"['CRDF', 'Dr.Web']\",0,0,0,0,0,1,0,2,\"['CRDF', 'Dr.Web']\",0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2001-11-08,8095,261,22,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,\"diegofusaro | Twitter, Instagram, Facebook, TikTok, Twitch | Linktree\",\"Filosofo, allievo indipendente di Hegel e Marx. Al di lÃ di destra e sinistra.\",,0.53535616,True\nhttps://kinokrad.cc/,kinokrad.cc,0,65,1,0,22,['Forcepoint ThreatSeeker'],0,0,0,0,0,1,0,1,['Forcepoint ThreatSeeker'],0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2016-11-24,2600,83,7,0,[],0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,100,\"Фильмы онлайн, смотреть бесплатно Кино онлайн в хорошем качестве\",Скучно? Начинайте смотреть фильмы онлайн бесплатно в хорошем качестве. Самая большая кинотека и удобная сортировка позволяет выбрать лучшее кино на любой вкус,\"смотреть, фильмы, онлайн, бесплатно\",0.6203251,False\nhttps://www.emailmeform.com/,emailmeform.com,-1,67,1,0,20,['CRDF'],0,0,0,0,0,1,0,1,['CRDF'],0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2006-10-23,6285,202,17,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,EmailMeForm: Free Online Form Builder and Survey Creator,\"Collect payments, customer data, registrations, event RSVPs, and leads with our secure online forms and surveys – use powerful templates or DIY. Sign up free.\",,0.66337323,True\nhttps://weixin110.qq.com/,weixin110.qq.com,0,68,1,0,19,['AutoShun'],0,0,0,0,0,1,0,1,['AutoShun'],0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,1995-05-04,10475,337,28,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,微信安全中心 - 安全连接一切,微信安全中心(weixin110.qq.com)，安全连接一切。你可以通过微信安全中心提供的各种安全工具管理微信账号安全，并获取最新的安全资讯。,\"微信安全中心,安全中心,微信110,微信账号安全问题,找回账号密码,关闭账号保护,账号自助解封,冻结账号,解冻账号,投诉维权,微信安全学堂\",0.69722223,False\nhttps://v.daum.net/,v.daum.net,0,68,1,0,19,['AutoShun'],0,0,0,0,0,1,0,1,['AutoShun'],0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,1996-03-05,10169,328,27,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,308 Permanent Redirect,,,0.69722223,False\nhttps://protonvpn.com/,protonvpn.com,3,68,1,0,19,['Seclookup'],0,0,0,0,0,1,0,1,['Seclookup'],0,0,0,0,0,1,0,1,0,0,0,True,1,['This is a a false positive. Sadly clean-mx.de does not answer e-mail or any other attempts to rectify this. '],True,True,2016-12-03,2591,83,7,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,\"Proton VPN: Fast, private, and secure VPN service | Proton VPN\",\"The safest VPN for browsing privately and accessing blocked content. Developed by CERN scientists, protected by Swiss privacy laws.\",,0.71937746,False\nhttps://xsite.singaporetech.edu.sg/,xsite.singaporetech.edu.sg,0,65,0,1,22,['Quttera'],0,0,0,0,0,0,1,1,['Quttera'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,2009-10-27,5185,167,14,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,xSiTe - Learning Management System (LMS) of Singapore Institute of Technology,\"xSiTe is Singapore Institute of Technology's Learning Management System (LMS) which is powered by Desire2Learn's Integrated Learning Platform - the industry's most user-friendly, intuitive learning environment. xSiTe is equipped with innovative teaching and learning tools that will support your unique learning preferences.\",\"SIT,LMS, learning management system, course management system, e-learning, eLearning, desire2learn, D2L, Singapore Institute of Technology\",0.739706,False\nhttps://libgen.is/,libgen.is,0,66,0,1,21,['alphaMountain.ai'],0,0,0,0,0,0,1,1,['alphaMountain.ai'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,2017-12-08,2221,71,6,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,100,Library Genesis,Library Genesis is a scientific community targeting collection of books on natural science disciplines and engineering.,,0.76008755,False\nhttps://timesofindia.indiatimes.com/,timesofindia.indiatimes.com,0,67,0,1,20,['Quttera'],0,0,0,0,0,0,1,1,['Quttera'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,1996-11-22,9907,319,27,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,\"News - Latest News, Breaking News, Bollywood, Sports, Business and Political News | Times of India\",\"Top News in India: Read Latest News on Sports, Business, Entertainment, Blogs and Opinions from leading columnists. Times of India brings the Breaking News and Latest News Headlines from India and around the World.\",\"News, Breaking news, Latest news, Live news, Today news, News Today, India news, English news, Politics news, Top news in India\",0.7835253,False\nhttps://hockey.fantasysports.yahoo.com/,hockey.fantasysports.yahoo.com,0,67,0,1,20,['Quttera'],0,0,0,0,0,0,1,1,['Quttera'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,1995-01-18,10581,341,28,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Fantasy Hockey 2023 | Fantasy Hockey | Yahoo! Sports,\"Yahoo Fantasy Hockey. Create or join a NHL league and manage your team with live scoring, stats, scouting reports, news, and expert advice.\",\"Fantasy Hockey, Free Fantasy Hockey\",0.7835253,False\nhttps://mail.rambler.ru/,mail.rambler.ru,0,67,0,1,20,['Quttera'],0,0,0,0,0,0,1,1,['Quttera'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,1996-09-26,9964,321,27,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Рамблер/почта – надежная и бесплатная электронная почта,\"Создайте электронную почту с надежной защитой от спама и вирусов! Рамблер/почта — удобный и быстрый почтовый ящик, к которому можно подключить несколько адресов и работать со всей входящей почтой через один интерфейс.\",\"рамблер почта, бесплатная почта, электронная почта, создать почту, регистрация почты, почта без спама, защита от спама, антиспам, бесконечный ящик, неограниченный ящик, неограниченный объем ящика, электронный почтовый ящик, почтовый ящик, бесплатная электронная почта\",0.7835253,False\nhttps://azure.k12net.com/,azure.k12net.com,0,0,0,0,88,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2006-03-08,6514,210,17,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,\"K12 OKULNET, Student Information System\",\"okul, k12, k12net, okulnet, automation, okul schools\",0.8589228,False\nhttps://www.launch.online-banking.hsbc.com.ar/,launch.online-banking.hsbc.com.ar,0,0,0,0,88,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2011-05-31,4604,148,12,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,55,,,,0.8589228,False\nhttps://phpmyadmin.mi-alojamiento.com/,phpmyadmin.mi-alojamiento.com,0,0,0,0,88,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2008-01-15,5836,188,15,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,60,phpMyAdmin,,,0.8589228,False\nhttps://webmail.sndi.ci/,webmail.sndi.ci,0,0,0,0,88,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2016-06-17,2760,89,7,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Apache2 Debian Default Page: It works,,,0.8589228,False\nhttps://www.lastpass.com/,lastpass.com,2,70,0,1,17,['ArcSight Threat Intelligence'],0,0,0,0,0,0,1,1,['ArcSight Threat Intelligence'],0,0,0,0,0,0,1,1,0,0,0,True,0,[],True,True,2005-03-08,6879,221,18,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,100,LastPass | Something went wrong,,,0.8749509,False\nhttps://www.clstjean.be/,clstjean.be,0,61,0,0,27,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,1996-06-04,10078,325,27,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Hôpital à Bruxelles – Clinique Saint Jean,\"La Clinique Saint Jean vous accueille au cœur de Bruxelles, sur ses 3 sites : Botanique, Méridien et Léopold 1. Nous sommes facilement accessibles via les transports en commun. Contactez-nous pour plus d’informations 02/221.91.11.\",,0.8851495,False\nhttps://arenabg.com/,arenabg.com,0,68,1,0,19,['SCUMWARE.org'],0,0,0,0,1,0,0,1,['SCUMWARE.org'],0,0,0,0,1,0,0,1,0,0,0,True,0,[],True,True,2003-06-04,7522,242,20,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Начало » ArenaBG,\"Гледай безплатно Филми и Сериали онлайн. Тук можете да изтеглите безплатни филми, сериали, музика, игри, софтуер и книги.\",,0.88788694,False\nhttps://www.axacolpatria.co/,axacolpatria.co,0,64,0,0,24,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2013-11-07,3713,119,10,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,IIS Windows Server,,,0.91580886,False\nhttps://uncpress.org/,uncpress.org,0,67,0,0,21,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2011-11-03,4448,143,12,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,The University of North Carolina Press,\"Shop our award-winning books, read samples, meet the authors, visit online exhibits, and learn more about our publishing process.\",,0.97277594,False\nhttps://drive.proton.me/,drive.proton.me,0,67,0,0,21,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2010-10-10,4837,156,13,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Proton Drive,Proton Drive allows you to securely store and share your sensitive documents and access them anywhere.,,0.97277594,False\nhttps://account.proton.me/,account.proton.me,0,68,0,0,20,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2010-10-10,4837,156,13,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Proton,\"Our encrypted services let you control who has access to your emails, plans, files, and online activity. Free plans are available.\",,0.9921838,False\nhttps://tw.stock.yahoo.com/,tw.stock.yahoo.com,0,68,0,0,20,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,1995-01-18,10581,341,28,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Yahoo奇摩股市,Yahoo奇摩股市提供國內外財經新聞，台股、期貨、選擇權、國際指數、外匯、港滬深股、美股等即時報價資訊，以及自選股、選股健診與多種分析工具，協助投資人快速制定投資策略。,,0.9921838,False\nhttps://zooniverse.org/,zooniverse.org,1,68,0,0,20,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,2008-10-28,5549,179,15,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,The Zooniverse is the world’s largest and most popular platform for people-powered research.,,1.0007803,False\nhttps://www.bbc.co.uk/,bbc.co.uk,2,68,0,0,20,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,1,\"['Scam - British people are forced to pay for this garbage with the enforced TV licence fee, whether they watch these channels or not.\\nMore US news than British.\\nRidiculously overpaid presenters.']\",True,True,1996-08-01,10020,323,27,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,BBC - Home,\"The best of the BBC, with the latest news and sport headlines, weather, TV & radio highlights and much more from across the whole of BBC Online.\",,1.0093993,False\nhttps://debian.org/,debian.org,1,69,0,0,19,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,1999-03-10,9069,292,24,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,Debian -- The Universal Operating System,Debian is an operating system and a distribution of Free Software. It is maintained and updated through the work of many users who volunteer their time and effort.,\"debian, GNU, linux, unix, open source, free, DFSG\",1.0206362,False\nhttps://www.americanexpress.com/,americanexpress.com,0,70,0,0,18,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,1,\"['#phishing\\nThis IOC was found in a paste: https://pastebin.com/mYTHys4W with the title \"\"20220831_PHISHING_SCAM_1\"\" by wavellan\\n\\nFor more information, or to report interesting/incorrect findings, contact us - bot@tines.io']\",True,True,1995-06-04,10444,336,28,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,\"American Express Credit Cards, Rewards & Banking\",\"American Express offers world-class Charge and Credit Cards, Gift Cards, Rewards, Travel, Personal Savings, Business Services, Insurance and more.\",,1.0329942,False\nhttps://docs.google.com/,docs.google.com,61,68,1,0,19,['MalwarePatrol'],0,0,0,0,0,1,0,1,['MalwarePatrol'],0,0,0,0,0,1,0,1,0,0,0,True,6,\"[\"\"This indicator was mentioned in a report.\\n\\n🔎 Title: Stealing More Than Towels: The New InfoStealer Campaign Hitting Hotels and Travel Agencies\\n📑 Reference: https://perception-point.io/blog/stealing-more-than-towels-the-new-infostealer-campaign-hitting-hotels-and-travel-agencies/\\n📆 Report Publish Date: 2023-09-18\\n🏷️ Reference ID: #f55b10bf9 (https://www.virustotal.com/gui/search/f55b10bf9/comments for report's related indicators)\\n\"\", 'Google Docs. Anyone with a Google account can create a \"\"Google Doc\"\", and while these can not contain JavaScript, they can link to phishing, scams, and malware.\\nThere is nothing inherently bad about this service, but it can be abused.\\n#google #usercontent', '#safe', 'It´s not always save, google docs is also used to distribute malware.\\nThis is a Malware Link:\\n', \"\"It's by Google, it's safe.\"\", '#top-1K #Google']\",True,True,1997-09-15,9610,310,26,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,100,,,,1.0575117,False\n\n\n\n\n\n\n\n\n\nThis data set is a data set in csv format, first of all, read it as csv format, the parameters in the top row are the parameters and the values of these parameters in the other bottom rows are the values of these parameters for that row and the is_safe parameter at the end should determine whether that site is safe or unsafe, if True, it should determine it as unsafe, if False, it should determine it as safe. This AI will actually input similar data and there will be no is_safe parameter at the end of this data. This AI will compare the data entered with the data above and at the end, it will be an AI that requires it to add a section at the end of that data as safe, unsafe, suspicious and how suspicious it is.\n\n\n\nA high value of vt_domain_reputation increases the reliability rate of the website, while a value less than 0 decreases this rate.\nA high value of vt_domain_harmless increases the reliability rate of the website; vt_domain_malicious, vt_domain_suspicious more than 0 decreases this rate.\nInspect the items in vt_domain_detailed_malicious and a high value of vt_domain_detailed_malicious also decreases the reliability rate.\nvt_domain_mal_reason_not_recommended,vt_domain_mal_reason_phishing,vt_domain_mal_reason_spam,vt_domain_mal_reason_spam,vt_domain_mal_reason_fraud,vt_domain_mal_reason_malware,vt_domain_mal_reason_malicious,vt_domain_mal_reason_suspicious values different from 0 indicate that antivirus engines consider that site suspicious. Therefore, if these values are different from 0, decrease the reliability rate value.\n\nvt_url_malicious greater than 0 decreases the reliability rate.\nInspect the items in vt_url_detailed_malicious and a high number of them will also reduce the reliability rate.\nvt_url_mal_reason_not_recommended,vt_url_mal_reason_phishing,vt_url_mal_reason_spam,vt_url_mal_reason_spam,vt_url_mal_reason_fraud,vt_url_mal_reason_malware,vt_url_mal_reason_malicious,vt_url_mal_reason_suspicious values different from 0 indicate that antivirus engines consider that site suspicious. Therefore, if these values are different from 0, decrease the reliability rate value.\n\nA value of 1 for cpai_disposition_clean increases the reliability rate, while a value of 0 for cpai_disposition_clean and a value of 1 for cpai_disposition_scam,cpai_disposition_suspicious,cpai_disposition_phish decreases the reliability rate.\n\nvirustotal_comments_comment_count indicates the number of comments written about that site in virustotal. If this value is different from 0, read the comments inside the virustotal_comments_comments values and classify those comments as positive or negative, if the comments there are positive about the site, increase the reliability rate value and if there are negative comments about that site, decrease the reliability rate value\n\n The apivoid_results_domain_age_in_days value shows when that site was created. If a site is newly established, it decreases the reliability value of that site.\nA high value of apivoid_results_detections decreases the website's reliability rate.\nInspect the items in the apivoid_results_detected_list and a high number of them also decreases the reliability rate.\napivoid_results_security_checks_is_suspended_site indicates that the site is suspicious by apivoid and a value of 1 decreases the reliability rate.\nI want you to pay attention to the apivoid_results_trust_score value. This value takes a value between 0 and 100. If this value is close to 0, it decreases the reliability rate value, and if it is close to 100, it increases the reliability rate value.\nWith the values from apivoid_results_web_page_title,apivoid_results_web_page_description,apivoid_results_web_page_keywords parameters, you can have information about that site and strengthen your interpretation accordingly.\n\nknn_result parameter is the most important parameter. \nBecause this parameter is the information of the reliability of that site calculated over 10000 data with kNN Classification. \nIf this value is close to 1, it should have a significant effect on increasing the reliability rate value of that site. \nAt the same time, if this value is close to 0, it should have a very important effect on decreasing the reliability rate value of that site.\nIf the knn_result value is less than 0 or very close to 0, it is not possible for the trustworthiness ratio to be more than 85.\nIf knn_result is less than 0, the reliability rate value is less than 70.\nIf knn_result is between 0 and 0.2, the reliability rate is less than 85.\nIf knn_result is between 0.9 and 1, the reliability rate is between 85 and 100.\n\n\n\n\n\nKeep in mind that this data represents a sample and you should fill in the blank spaces provided below.\nOutput: The reliability rate of this blank site is determined as % and the category of this site in terms of security is blank.\nYou need to give the parameter named knn_result the highest priority. Because this parameter is the average reliability value of that data with kNN Classification in a data set created with more of these data. The more that value is, the higher the reliability.\nIf it is close to 0, lower the reliability. If it is close to 1, increase its reliability.\nThe value in the first blank will contain the domain of the website entered.\n\n\nThe value in the second blank will be a numeric value and the probability that the website is reliability will be calculated and written here. \n\n\n\n\n\nThe value in the third blank will be one of Safe, Suspicious, Malicious. These values are based on the reliability probability calculated in the second blank and are the values that reliability should take in the following cases.\nSafe if the calculated value is between 85-100\nSuspicious if the calculated value is between 70-85\nMalicious if the calculated value is between 0-70\nStick to these ratios. Make sure that the value you give is in the correct range above.\nYou will only use these 3 Safe, Suspicious and Malicious and the probability of trustworthiness will be this calculated value.\n\nNo reliability value should be 100 and the maximum value should be 99.\n\nExamine the sample data, answers and reliability rate values below. Use this data but do not choose the exact same reliability rate value.\n\nhttp://polrac.com/,polrac.com,0,56,11,0,21,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CRDF', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,11,\"['Sophos', 'Fortinet', 'alphaMountain.ai', 'Lionic', 'Avira', 'SOCRadar', 'BitDefender', 'G-Data', 'CRDF', 'CyRadar', 'Antiy-AVL']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2023-06-29,192,6,0,1,['CRDF'],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,,,,-0.006778449:The reliability rate of this polrac.com site is determined as 12% and the category of this site in terms of security is Malicious.\nhttps://kon-vert-or.top/,kon-vert-or.top,0,63,4,0,21,\"['Seclookup', 'CyRadar', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,4,\"['Seclookup', 'CyRadar', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,False,,,,,0,[],0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,1,0,35,,,,0.022913069:The reliability rate of this kon-vert-or.top site is determined as 36% and the category of this site in terms of security is Malicious.\nhttp://ikonni.com/,ikonni.com,0,66,3,0,19,\"['CRDF', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,3,\"['CRDF', 'Xcitium Verdict Cloud', 'SOCRadar']\",0,1,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2017-11-12,2247,72,6,1,['CRDF'],0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,Home - IKONNI,,,0.027657896:The reliability rate of this ikonni.com site is determined as 57% and the category of this site in terms of security is Malicious.\nhttp://paypalsupport.mtxserv.fr/,paypalsupport.mtxserv.fr,0,66,1,0,21,['Webroot'],0,0,0,0,0,1,0,1,['Webroot'],0,0,0,0,0,1,0,0,0,1,0,True,0,[],True,True,2009-09-14,5228,168,14,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,65,,,,0.35480797:The reliability rate of this paypalsupport.mtxserv.fr site is determined as 78% and the category of this site in terms of security is Suspicious.\nhttp://electra-amor.webcindario.com/,electra-amor.webcindario.com,0,65,1,0,22,['CyRadar'],0,0,0,0,0,1,0,1,['CyRadar'],0,0,0,0,0,1,0,1,0,0,0,True,0,[],True,True,2001-02-28,8348,269,22,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,100,,,,0.6203251:The reliability rate of this electra-amor.webcindario.com site is determined as 81% and the category of this site in terms of security is Suspicious.\nhttps://uk.yahoo.com/,uk.yahoo.com,0,69,0,0,19,[],0,0,0,0,0,0,0,0,[],0,0,0,0,0,0,0,1,0,0,0,True,0,[],True,True,1995-01-18,10581,341,28,0,[],0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,100,,,,1.0116866,False:The reliability rate of this uk.yahoo.com site is determined as 99% and the category of this site in terms of security is Safe.\n\n\n\n{data}",
    ]

    # Geliştirilen prompt ile Gemini'den yanıt alınır ve geri döndürülür.
    print('Gemini Processsing...')
    response = model.generate_content(prompt_parts)
    print('Gemini Processed!')
    print(response.text)
    return response.text

# Sadece domaine bakılarak Gemini ortamında o domainin güvenli olup olmadığına bakan fonksiyon
def get_gemini_result_for_domain(url, ge_key):

    genai.configure(api_key=ge_key)

    # Gemini'nin yanıt verme ayarları yapılır.
    generation_config = {
    "temperature": 0.9,
    "top_p": 1,
    "top_k": 1,
    "max_output_tokens": 2048,
    }
    # Gemini'nin güvenilirlik ayarları yapılır.
    safety_settings = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    ]

    # Gemini'ye model ve ayarlar yüklenir.
    model = genai.GenerativeModel(model_name="gemini-pro",
                                generation_config=generation_config,
                                safety_settings=safety_settings)
    
    # Önceden oluşturulmuş prompt yüklenir.
    prompt_parts = [
        f"\nBrowser Alerts and Download Powers:\nFeature: Malicious sites may attempt to infect users with malware by displaying browser alerts or forcing downloads.\nExample: yourpcvirusinfected-alert.com\n\nPhishing Pages:\nDescription: Malicious sites may attempt to steal users' passwords, often by mimicking the login pages of popular service providers.\nExample: paypall-login-securepage.com\n\nSensitive Information Requests:\nFeature: Malicious sites can phish by requesting sensitive information from users.\nExample: verify-your-bank-account-info-now.com\n\nIn the light of this information, I will ask you to output the domains I will give you as follows.\nhttps://www.deepl.com/ is safe.\nhttps://www.google.com/ is safe.\nhttp://paypal-support.valid144.tk/ is not safe.\n\nYou will interpret this ... with the features in the malicious domain I have given you above.\n\nI will send you some sample answers and you can respond based on these answers.\nhtttp://loremipsum.com is not safe.\nhttps://azizatikfl.meb.k12.tr/ is safe.\nYou can give 2 types of answers:\nInput is not safe.\nInput is safe.\nthese two.\n\n{url}",
    ]
    # Geliştirilen prompt ile Gemini'den yanıt alınır ve geri döndürülür.
    response = model.generate_content(prompt_parts)
    return response.text





def start(target_url):
    # API anahtarlarını ve proxy'yi tanımla
    ge_key = "ENTER_GEMINI_API_KEY"
    vt_key = 'ENTER_VIRUSTOTAL_API_KEY'
    cp_key = 'ENTER_CHECKPHISH_AI_API_KEY'
    av_key = 'ENTER_APIVOID_API_KEY' 
    proxy = 'ENTER_PROXY'

    # Domain'i çıkarmak için regex paterni
    domain_pattern = r'https?:\/\/(?:www\.)?([^\/]+)'
    
    # Hedef URL'den domain'i çıkar
    domain = re.findall(domain_pattern, target_url)[0]

    # Toplam sonuçları saklamak için bir JSON nesnesi oluştur
    overall_result = json.loads('{}')
    overall_result['url'] = target_url
    overall_result['domain'] = domain
    print(f'Target URL: {target_url} | Domain: {domain}')
    
    # Çalışma süresini ölçmek için başlangıç zamanını kaydet
    started_time = time.time()
    
    # Concurrent Futures kullanarak çeşitli işlemleri eşzamanlı olarak yürüt
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_function = {
            executor.submit(scan_domain_virustotal, domain, vt_key, proxy): 'virustotal_domain_results',
            executor.submit(scan_url_virustotal, target_url, vt_key, proxy): 'virustotal_url_results',
            executor.submit(comment_virustotal, domain, vt_key, proxy): 'virustotal_comments',
            executor.submit(main_checkphishai, domain, cp_key, proxy): 'checkphishai_results',
            executor.submit(check_apivoid, domain, av_key, proxy): 'apivoid_results',
        }

        for future, result_key in future_to_function.items():
            try:
                result = future.result()
                overall_result[result_key] = result
            except Exception as e:
                overall_result[result_key] = {'error': str(e)}

    # Bitiş zamanını kaydet
    finished_time = time.time()
    # Geçen süreyi saniye cinsinden hesapla
    elapsed_time = str(int(finished_time - started_time))

    print(f'''Target URL => {target_url} | Total Elapsed Time => {elapsed_time}''')

    # Toplam sonuçları dosyaya kaydet
    save_data(overall_result)

    # CSV formatına dönüştürülmüş veriyi elde et
    df = get_csv_version(overall_result)

    # K-NN (K Nearest Neighbors) algoritması ile sonucu al
    knn_result = get_knn_result(df)[0]

    # Tüm sonuçlara K-NN sonucunu ekle
    overall_result['knn_result'] = knn_result
    print(f"Domain: {domain} | Predicted Value: {knn_result}")

    # Gemini AI'dan o sitenin güvenilirlik yüzdesiyle ilgili sonuçları al
    df_data = get_csv_version_for_gemini(overall_result)
    ai_result = get_gemini_result(df_data, ge_key)
    print('Gemini Result All Data: ' + ai_result)

    # Gemini AI'den domain sonuçlarını al
    ai_domain_result = get_gemini_result_for_domain(target_url, ge_key)
    print('Gemini Domain Data:', ai_domain_result)

    # Sonuçları bir sözlük içinde döndür
    return {'ai_data_result': ai_result, 'ai_domain_result': ai_domain_result}

print('Configuring Server...')
# Flask uygulamasını oluştur
app = Flask(__name__)
CORS(app)

# API'yi tanımla
@app.route('/', methods=['POST'])
def main():
    try:
        # Gelen JSON verisini al
        data = request.json
        site = data['site']

        # İşlemleri başlat ve sonucu döndür
        response = start(site)
        return jsonify(response), 200

    except Exception as e:
        print(e)
        # Hata durumunda hata mesajını döndür
        error_response = {"error": str(e)}
        return jsonify(error_response), 500


# Uygulamayı başlat
if __name__ == '__main__':
    app.run(debug=True)