import pymongo
from datetime import datetime


# Cipher Suites recommended by the Bundesamt fuer Sicherheit in der Informationstechnik for TLS 1.2
RECOMMENDED_CIPHER_SUITES = ['ECDHE-ECDSA-AES128-SHA256',
                             'ECDHE-ECDSA-AES256-SHA384',
                             'ECDHE-RSA-AES128-SHA256',
                             'ECDHE-RSA-AES256-SHA384',
                             'DHE-DSS-AES128-SHA256',
                             'DHE-DSS-AES128-GCM-SHA256',
                             'DHE-DSS-AES256-SHA384',
                             'DHE-DSS-AES256-GCM-SHA384',
                             'DHE-RSA-AES128-SHA256',
                             'DHE-RSA-AES128-GCM-SHA256',
                             'DHE-RSA-AES256-SHA256',
                             'DHE-RSA-AES256-GCM-SHA384',
                             'ECDH-ECDSA-AES128-SHA256',
                             'ECDH-ECDSA-AES128-GCM-SHA256',
                             'ECDH-ECDSA-AES256-SHA384',
                             'ECDH-ECDSA-AES256-GCM-SHA384',
                             'ECDH-RSA-AES128-SHA256',
                             'ECDH-RSA-AES128-GCM-SHA256',
                             'ECDH-RSA-AES256-SHA384',
                             'ECDH-RSA-AES256-GCM-SHA384']


def get_collection(collection_name):
    db_conn = pymongo.MongoClient('mongodb://localhost:27017/')
    db = db_conn.sslyze
    return db[collection_name]


def print_results(results):
    for result in results:
        print result


def percent(findings, base_value):
    return findings/(base_value/100.0)


def percent_output(findings, base_value):
    return '\t\t=> ' + str(round(percent(findings, base_value), 2)) + ' %'


def generate_output(text, findings, base_value):
    return text + ':\t\t' + str(findings) + '/' + str(base_value) + percent_output(findings, base_value)


def generate_headline_output(text):
    output = ('-' * 70) + '\n' + text.upper() + '\n'
    output += ('=' * len(text))
    return output


def dane_support():
    print generate_headline_output('dane support')
    collection = get_collection('dane')
    all_documents = collection.find({})

    base_value = all_documents.count()

    results = collection.find({'results.isSupported': True})
    findings = results.count()
    print generate_output('DANE supported with TLSA', findings, base_value)

    results = collection.find({'$and': [{'results.isSupported': True}, {'results.validated': True}]})
    findings = results.count()
    print generate_output('DANE validated', findings, base_value)

    results = collection.find({'results.dnssecValidated': True})
    findings = results.count()
    print generate_output('DNSSEC validated', findings, base_value)

    results = collection.find({'$and': [{'results.isSupported': True}, {'results.validated': True}, {'results.dnssecValidated': True}]})
    findings = results.count()
    print generate_output('DANE + DNSSEC validated', findings, base_value)


def heartbleed_vulnerability():
    print generate_headline_output('heartbleed vulnerability')
    collection = get_collection('heartbleed')
    all_documents = collection.find({})

    results = collection.find({'results.isVulnerable': True})
    findings, base_value = results.count(), all_documents.count()
    print generate_output('Vulnerable for Heartbleed', findings, base_value)


def tls_support(tls_version):
    print generate_headline_output('tls support for ' + tls_version)
    collection = get_collection(tls_version)
    all_documents = collection.find()

    results = collection.find({'$where': 'this.results.acceptedCipherSuites.length > 0'}, {'results.acceptedCipherSuites': 1})
    findings, base_value = results.count(), all_documents.count()
    print generate_output('Targets which support ' + tls_version, findings, base_value)


def cert_validity_with_key_length():
    print generate_headline_output('certificate validity with key length')
    collection = get_collection('certinfo')
    all_documents = collection.find({})

    delta_days_sum = 0
    count_deltas = {}

    date_format_1 = '%b %d %H:%M:%S %Y %Z'
    date_format_2 = '%b %d %H:%M:%S %Y'
    for document in all_documents:
        results = document['results']
        if 'certificateChain' in results:
            cert = results['certificateChain'][0]
            if 'rsaEncryption' in cert['subjectPublicKeyInfo']['publicKeyAlgorithm']:
                validity = cert['validity']
                not_before, not_after = validity['notBefore'], validity['notAfter']
                try:
                    not_before_date = datetime.strptime(not_before, date_format_1)
                except ValueError:
                    not_before_date = datetime.strptime(not_before, date_format_2)
                try:
                    not_after_date = datetime.strptime(not_after, date_format_1)
                except ValueError:
                    not_after_date = datetime.strptime(not_after, date_format_2)

                delta = not_after_date - not_before_date
                delta_days = delta.days
                delta_years = int(round(delta_days/365.0, 0))
                #delta_years = delta_days/365
                delta_days_sum += delta_days

                key_length = int(cert['subjectPublicKeyInfo']['publicKeySize'])
                if delta_years in count_deltas:
                    if key_length in count_deltas[delta_years]:
                        count_deltas[delta_years][key_length] += 1
                    else:
                        count_deltas[delta_years][key_length] = 1
                else:
                    count_deltas[delta_years] = {key_length: 1}
            else:
                print 'Other algorithm used for public key:\t' + str(cert['subjectPublicKeyInfo'])

    avg_delta_days = delta_days_sum/all_documents.count()
    avg_delta_years = avg_delta_days/365.0
    print 'Average certificate validity in years:', round(avg_delta_years, 2)

    # Generate tikz chart
    #for validity in sorted(count_deltas):
    #    if validity > 0:
    #        amount_per_key_length = count_deltas[validity]
    #        for key_length in sorted(amount_per_key_length):
    #            amount = amount_per_key_length[key_length]
    #            if amount > 10:
    #                print str(validity) + '\t' + str(key_length/1000.0) + '\t' + str(amount)


def cert_key_length():
    print generate_headline_output('certificate key length')
    collection = get_collection('certinfo')
    all_documents = collection.find({})
    count_all = all_documents.count()

    key_size_count = {'x<1024': 0,
                      '1024<=x<2048': 0,
                      '2048<=x<4096': 0,
                      '4096<=x<8192': 0,
                      '8192<=x': 0,
                      'other_algorithm_used': 0}

    count_analyzed = 0
    keysize_sum_over_all = 0
    for document in all_documents:
        results = document['results']
        if 'certificateChain' in results:
            cert = results['certificateChain'][0]
            if 'rsaEncryption' in cert['subjectPublicKeyInfo']['publicKeyAlgorithm']:
                key_size = int(cert['subjectPublicKeyInfo']['publicKeySize'])
                if key_size < 1024:
                    key_size_count['x<1024'] += 1
                elif key_size < 2048:
                    key_size_count['1024<=x<2048'] += 1
                elif key_size < 4096:
                    key_size_count['2048<=x<4096'] += 1
                elif key_size < 8192:
                    key_size_count['4096<=x<8192'] += 1
                else:
                    key_size_count['8192<=x'] += 1
                keysize_sum_over_all += key_size
            else:
                #print 'Other algorithm used for public key:\t' + str(cert['subjectPublicKeyInfo'])
                key_size_count['other_algorithm_used'] += 1
            count_analyzed += 1

    print 'Average keylength: ' + str(keysize_sum_over_all/float(count_analyzed))

    for key_size in sorted(key_size_count):
        print generate_output('Keylength ' + key_size, key_size_count[key_size], count_analyzed)


def cert_chain_validation():
    print generate_headline_output('certificate chain validation')
    collection = get_collection('certinfo')
    all_documents = collection.find({})
    count_all = all_documents.count()

    results = {'self signed certificate': 0,
               'ok': 0,
               'unable to get local issuer certificate': 0,
               'certificate has expired': 0,
               'self signed certificate in certificate chain': 0,
               'unsupported certificate purpose': 0,
               'others': 0}

    for document in all_documents:
        if 'certificateValidations' in document['results']:
            all_validations = {'self signed certificate': True,
                               'ok': True,
                               'unable to get local issuer certificate': True,
                               'certificate has expired': True,
                               'self signed certificate in certificate chain': True,
                               'unsupported certificate purpose': True}

            # Run through trust store validation results
            for validation in document['results']['certificateValidations']:
                if 'validationResult' in validation:
                    validation_result = validation['validationResult']
                    if not 'self signed certificate' in validation_result:
                        all_validations['self signed certificate'] = False
                    if not 'ok' in validation_result:
                        all_validations['ok'] = False
                    if not 'unable to get local issuer certificate' in validation_result:
                        all_validations['unable to get local issuer certificate'] = False
                    if not 'certificate has expired' in validation_result:
                        all_validations['certificate has expired'] = False
                    if not 'self signed certificate in certificate chain' in validation_result:
                        all_validations['self signed certificate in certificate chain'] = False
                    if not 'unsupported certificate purpose' in validation_result:
                        all_validations['unsupported certificate purpose'] = False

            found_one = False
            for validation_result in all_validations:
                if all_validations[validation_result]:
                    results[validation_result] += 1
                    found_one = True
                    break
            if not found_one:
                results['others'] += 1

    for key in sorted(results):
        print generate_output(key, results[key], count_all)


def cert_validity():
    print generate_headline_output('certificate validity')
    collection = get_collection('certinfo')
    all_documents = collection.find({})

    validity_days_amount = {}

    validity_sum = 0
    validity_sum_counter = 0

    date_format_1 = '%b %d %H:%M:%S %Y %Z'
    date_format_2 = '%b %d %H:%M:%S %Y'
    for document in all_documents:
        results = document['results']
        if 'certificateChain' in results:
            cert = results['certificateChain'][0]
            if 'rsaEncryption' in cert['subjectPublicKeyInfo']['publicKeyAlgorithm']:
                validity = cert['validity']
                not_before, not_after = validity['notBefore'], validity['notAfter']
                try:
                    not_before_date = datetime.strptime(not_before, date_format_1)
                except ValueError:
                    not_before_date = datetime.strptime(not_before, date_format_2)
                try:
                    not_after_date = datetime.strptime(not_after, date_format_1)
                except ValueError:
                    not_after_date = datetime.strptime(not_after, date_format_2)

                delta = not_after_date - not_before_date
                delta_years = delta.days/365
                validity_sum += delta_years
                validity_sum_counter += 1
                if delta_years in validity_days_amount:
                    validity_days_amount[delta_years] += 1
                else:
                    validity_days_amount[delta_years] = 1
            else:
                print 'Other algorithm used for public key:\t' + str(cert['subjectPublicKeyInfo'])

    print 'Average validity period in years: ' + str(validity_sum/float(validity_sum_counter))

    # Tikz scatter chart output
    #for days in sorted(validity_days_amount):
    #    amount = validity_days_amount[days]
    #    if 0 < days <= 40:# and amount > 10:
    #        print '(' + str(days) + ',' + str(amount/100.0) + ')'


def cert_validity_selfsigned_ok():
    print generate_headline_output('certificate validity comparison')
    collection = get_collection('certinfo')
    all_documents = collection.find({})

    validity_days_amount = {'selfsigned': {},
                            'validated': {}}

    validity_sum = {'selfsigned': 0,
                    'validated': 0}
    validity_sum_counter = {'selfsigned': 0,
                            'validated': 0}

    date_format_1 = '%b %d %H:%M:%S %Y %Z'
    date_format_2 = '%b %d %H:%M:%S %Y'
    for document in all_documents:
        results = document['results']
        if 'certificateChain' in results:
            cert = results['certificateChain'][0]
            if 'rsaEncryption' in cert['subjectPublicKeyInfo']['publicKeyAlgorithm']:
                validity = cert['validity']
                not_before, not_after = validity['notBefore'], validity['notAfter']
                try:
                    not_before_date = datetime.strptime(not_before, date_format_1)
                except ValueError:
                    not_before_date = datetime.strptime(not_before, date_format_2)
                try:
                    not_after_date = datetime.strptime(not_after, date_format_1)
                except ValueError:
                    not_after_date = datetime.strptime(not_after, date_format_2)

                delta = not_after_date - not_before_date
                delta_years = delta.days/365
                validation_result = None
                for validation in document['results']['certificateValidations']:
                    if 'validationResult' in validation and 'ok' in validation['validationResult']:
                        validation_result = 'validated'
                        break
                if not validation_result:
                    for validation in document['results']['certificateValidations']:
                        if 'validationResult' in validation and 'self signed certificate' in validation['validationResult']:
                            validation_result = 'selfsigned'
                            break
                if validation_result:
                    validity_sum[validation_result] += delta_years
                    validity_sum_counter[validation_result] += 1
                    if delta_years in validity_days_amount[validation_result]:
                        validity_days_amount[validation_result][delta_years] += 1
                    else:
                        validity_days_amount[validation_result][delta_years] = 1
            else:
                print 'Other algorithm used for public key:\t' + str(cert['subjectPublicKeyInfo'])

    print 'Average validity period in years for selfsigned certs: ' + str(validity_sum['selfsigned']/float(validity_sum_counter['selfsigned']))
    print 'Average validity period in years for validated certs: ' + str(validity_sum['validated']/float(validity_sum_counter['validated']))

    # Tikz scatter chart output
    print '\n=> SELF-SIGNED'
    for days in sorted(validity_days_amount['selfsigned']):
        amount = validity_days_amount['selfsigned'][days]
        if 0 < days:# <= 40:
            print '(' + str(days) + ',' + str(amount/100.0) + ')'
    print '\n=> VALIDATED'
    for days in sorted(validity_days_amount['validated']):
        amount = validity_days_amount['validated'][days]
        if 0 < days:# <= 40:
            print '(' + str(days) + ',' + str(amount/100.0) + ')'


def check_support_tls_versions():
    tls_support('sslv2')
    tls_support('sslv3')
    tls_support('tlsv1')
    tls_support('tlsv1_1')
    tls_support('tlsv1_2')


def cipher_suites(tls_version):
    print generate_headline_output('cipher suites for ' + tls_version)
    collection = get_collection(tls_version)
    all_documents = collection.find({})

    cipher_suite_usages = {}
    counter = 0
    for document in all_documents:
        if 'results' in document:
            target_results = document['results']
            if 'acceptedCipherSuites' in target_results:
                accepted_suites = target_results['acceptedCipherSuites']
                if len(accepted_suites) > 0:
                    for accepted_suite in accepted_suites:
                        suite_name = accepted_suite['name']
                        if suite_name in cipher_suite_usages:
                            cipher_suite_usages[suite_name] += 1
                        else:
                            cipher_suite_usages[suite_name] = 1
            if 'isProtocolSupported' in target_results and target_results['isProtocolSupported']:
                counter += 1

    usage_sum = {'good': 0, 'bad': 0}
    usage_counter = {'good': 0, 'bad': 0}
    for cs_name, cs_usage in sorted(cipher_suite_usages.items(), key=lambda x: x[1], reverse=True):
        if cs_name in RECOMMENDED_CIPHER_SUITES:
            recommendation_type = 'good'
        else:
            recommendation_type = 'bad'
        usage_sum[recommendation_type] += cs_usage/float(counter)
        usage_counter[recommendation_type] += 1
        print recommendation_type + ': ' + generate_output(cs_name, cs_usage, counter)
    #if not usage_counter['bad'] == 0:
    #    print 'Bad percentage:', usage_sum['bad']/usage_counter['bad']
    #if not usage_counter['good'] == 0:
    #    print 'Good percentage:', usage_sum['good']/usage_counter['good']


def check_support_cipher_suites_for_tls_versions():
    #cipher_suites('sslv2')
    #cipher_suites('sslv3')
    #cipher_suites('tlsv1')
    #cipher_suites('tlsv1_1')
    cipher_suites('tlsv1_2')


def check_support_only_bsi_recommended_cipher_suites():
    print generate_headline_output('check which targets support only bsi recommended cipher suites')
    collection = get_collection('tlsv1_2')
    all_documents = collection.find({})

    cipher_suite_usages = {'recommended': 0,
                           'not_recommended': 0}
    protocol_supported_counter = 0
    for document in all_documents:
        target_results = document['results']
        if 'isProtocolSupported' in target_results and target_results['isProtocolSupported']:
            protocol_supported_counter += 1
            if 'results' in document:
                target_results = document['results']
                if 'acceptedCipherSuites' in target_results:
                    accepted_suites = target_results['acceptedCipherSuites']
                    if len(accepted_suites) > 0:
                        for accepted_suite in accepted_suites:
                            recommended = 'recommended'
                            if not accepted_suite['name'] in RECOMMENDED_CIPHER_SUITES:
                                recommended = 'not_recommended'
                                break
                        cipher_suite_usages[recommended] += 1

    print generate_output('Targets which support only BSI recommended cipher suites', cipher_suite_usages['recommended'], protocol_supported_counter)
    print generate_output('Targets which support not only BSI recommended cipher suites', cipher_suite_usages['not_recommended'], protocol_supported_counter)


def check_support_not_only_bsi_recommended_cipher_suites():
    print generate_headline_output('check which targets support only bsi recommended cipher suites')
    collection = get_collection('tlsv1_2')
    all_documents = collection.find({})

    cipher_suite_usages = {'recommended': 0,
                           'not_recommended': 0}
    protocol_supported_counter = 0
    for document in all_documents:
        target_results = document['results']
        if 'isProtocolSupported' in target_results and target_results['isProtocolSupported']:
            protocol_supported_counter += 1
            if 'results' in document:
                target_results = document['results']
                if 'acceptedCipherSuites' in target_results:
                    accepted_suites = target_results['acceptedCipherSuites']
                    if len(accepted_suites) > 0:
                        for accepted_suite in accepted_suites:
                            recommended = 'not_recommended'
                            if accepted_suite['name'] in RECOMMENDED_CIPHER_SUITES:
                                recommended = 'recommended'
                                break
                        cipher_suite_usages[recommended] += 1

    print generate_output('Targets which support only BSI non-recommended cipher suites', cipher_suite_usages['recommended'], protocol_supported_counter)
    print generate_output('Targets which support not only BSI non-recommended cipher suites', cipher_suite_usages['not_recommended'], protocol_supported_counter)


def bsi_check():
    check_support_only_bsi_recommended_cipher_suites()
    check_support_not_only_bsi_recommended_cipher_suites()


def main():
    #dane_support()
    #cert_chain_validation()
    #cert_key_length()
    #cert_validity_selfsigned_ok()
    #check_support_tls_versions()
    #check_support_cipher_suites_for_tls_versions()
    #bsi_check()
    #heartbleed_vulnerability()

    #cert_validity()
    #cert_validity_with_key_length()
    pass


if __name__ == "__main__":
    try:
        main()
    except pymongo.errors.ConnectionFailure, e:
        print "Could not connect to MongoDB: %s" % e
