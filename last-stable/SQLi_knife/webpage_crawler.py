import re
from urllib.parse import urlparse



# Crawls all available link one by one with nyawc - powerfull library that enables you to test your payload against all requests of a certain domain.


"""
the process consist of 4 stages

1. crawler_before_start

2*n. request_before_start - many times

3*n. request_after_finish - many times

4. crawler_after_finish

we can do some action at each stage

"""


class WebpageCrawler:
    def __init__(self):
        """
        runs when object initialized

        # list of crawled urls
        self.crawled = []
        # define steps og crawling as described above
        options = Options()
        # depth of crawling means depth in url tree.
        # for  ex apple.com and apple.com/buy has depth 1, but apple.com/buy/iphone11 has depth 2 if the only one link available
        options.scope.max_depth = 1
        # nothing to do before start.  lambda: None is an empty action equal to def my_def(): pass
        options.callbacks.crawler_before_start = lambda: None
        # nothing to do after finish .  lambda: None is an empty action equal to def my_def(): pass
        options.callbacks.crawler_after_finish = lambda queue: None
        # let nyawc to contine crawling before each request
        options.callbacks.request_before_start = lambda queue, queue_item: CrawlerActions.DO_CONTINUE_CRAWLING
        # call request_after_finish method after request

        options.callbacks.request_after_finish = self.request_after_finish
        self.crawler = nyawcCrawler(options)
        """

    # entry point method to crawl some url (get all links available)
    def crawl_url(self, url):
        """
        :param url: url for crawling
        :return: list of crawled urls  as result crawling
        """
        self.crawled = []
        return self.crawled
    """"""
    # method that runs after each request is done
    def request_after_finish(self, queue, queue_item, new_queue_items):
        """
        :param queue: - nyawc mandatory parameter, just ignore it
        :param queue_item: item of proceccing, request
        :param new_queue_items: - nyawc mandatory parameter, just ignore it
        :return:
        """
        pass
        """
        # get url crawled
        current_url = queue_item.request.url
        # regular expression to check if some of php, asp etc ot parameters exists
        regexp_links = '(.*?)(.php\?|.asp\?|.apsx\?|.jsp\?)(.*?)=(.*?)'
        # search by regular expression
        if re.search(regexp_links, current_url):
            # add to crawled list if is is not there yet
            if not current_url in self.crawled:
                self.crawled.append(current_url)
        # let nyawc to contine crawling
        return CrawlerActions.DO_CONTINUE_CRAWLING
        """