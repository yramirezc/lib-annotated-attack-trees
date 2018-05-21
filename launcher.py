
import sys
import os
# from extractor_bow import BoWExtractor
from query_as_root import QueryBasedEnricher 
# from extractor_bigrams import BigramExtractor
from extractor_tuples import TupleExtractor

# if sys.argv[1] == '-xbow':   # Deprecated
#     # argv[2]: NVD folder
#     # argv[3]: stopwords
#     indexer = BoWExtractor(sys.argv[2], sys.argv[3])
#     indexer.do_extraction()
# elif sys.argv[1] == '-xbigr':   # Deprecated
#     # argv[2]: NVD folder
#     # argv[3]: stopwords
#     # argv[4]: skip
#     indexer = BigramExtractor(sys.argv[2], sys.argv[3], int(sys.argv[4]))
#     indexer.do_extraction()
#elif sys.argv[1] == '-xtup':
if sys.argv[1] == '-xtup':
    # argv[2]: NVD folder
    # argv[3]: parser output folder
    # argv[4]: stopwords
    indexer = TupleExtractor(sys.argv[2], sys.argv[3], sys.argv[4], range(2013,2018))
    indexer.do_extraction()
elif sys.argv[1] == '-q':
    # argv[2]: terms for assumptions
    # argv[3]: terms for guarantees
    # argv[4,...]: query
    builder = QueryBasedEnricher(sys.argv[2], sys.argv[3], True, False)
    #builder = QueryBasedEnricher(sys.argv[2], sys.argv[3], False)
    builder.build_from_query(set(sys.argv[4 : len(sys.argv)]))
# elif sys.argv[1] == '-xbowq':   # Deprecated
#     # argv[2]: NVD JSON database
#     # argv[3]: stopwords
#     # argv[4,...]: query
#     indexer = BoWExtractor(sys.argv[2], sys.argv[3])
#     indexer.do_extraction()
#     builder = QueryBasedEnricher(os.path.join(os.path.dirname(sys.argv[2]), 'facts-ant-bows.txt'), 
#                                  os.path.join(os.path.dirname(sys.argv[2]), 'facts-cons-bows.txt'))
#     builder.build_from_query(set(sys.argv[4 : len(sys.argv)]))
    