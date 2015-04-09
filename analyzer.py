import pymongo


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


def main():
    dane_support()
    heartbleed_vulnerability()
    tls_support('sslv2')
    tls_support('sslv3')
    tls_support('tlsv1')
    tls_support('tlsv1_1')
    tls_support('tlsv1_2')


if __name__ == "__main__":
    try:
        main()
    except pymongo.errors.ConnectionFailure, e:
        print "Could not connect to MongoDB: %s" % e
