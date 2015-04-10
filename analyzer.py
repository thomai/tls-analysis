import pymongo
from datetime import datetime


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


def dane_support():
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
    collection = get_collection('heartbleed')
    all_documents = collection.find({})

    results = collection.find({'results.isVulnerable': True})
    findings, base_value = results.count(), all_documents.count()
    print generate_output('Vulnerable for Heartbleed', findings, base_value)


def tls_support(tls_version):
    collection = get_collection(tls_version)
    all_documents = collection.find()

    results = collection.find({'$where': 'this.results.acceptedCipherSuites.length > 0'}, {'results.acceptedCipherSuites': 1})
    findings, base_value = results.count(), all_documents.count()
    print generate_output('Targets which support ' + tls_version, findings, base_value)


def cert_validity():
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
    collection = get_collection('certinfo')
    all_documents = collection.find({})
    count_all = all_documents.count()

    key_size_count = {'x<1024': 0,
                      '1024<=x<2048': 0,
                      '2048<=x<4096': 0,
                      '4096<=x<8192': 0,
                      '8192<=x': 0}

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

    for key_size in sorted(key_size_count):
        print generate_output('Keylength ' + key_size, key_size_count[key_size], count_all)


def main():
    #dane_support()
    #heartbleed_vulnerability()
    #tls_support('sslv2')
    #tls_support('sslv3')
    #tls_support('tlsv1')
    #tls_support('tlsv1_1')
    #tls_support('tlsv1_2')
    #cert_validity()
    cert_key_length()
    pass


if __name__ == "__main__":
    try:
        main()
    except pymongo.errors.ConnectionFailure, e:
        print "Could not connect to MongoDB: %s" % e
