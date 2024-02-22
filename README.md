## HOST3R


<p align="center">
<img src="https://www.rbcafe.com/wp-content/uploads/host3r_python_script.png" alt="host3r" width="400">
</p>

host3r is a python tool that is designed to enumerate the subdomains of a specific domain to ban. Generate a search of the subdomains and paste the results to your /etc/hosts file. Generate a search of the subdomains and save the results to a text file...


## Installation

```
git clone https://github.com/rbcafe/host3r
```

## Recommended Python Version:

The recommended python version to use is 2.7.15 and 3.7.3

## Dependencies:

argparse : dnspython : requests

```
pip install argparse dnspython requests
```

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-h            | --help        | show the help message and exit
-d            | --domain      | Domain name to enumerate subdomains of
-o            | --output      | Save the results to a text file
-v            | --verbose     | Enable the verbosity
-e            | --exception   | Enable the exceptions notices
-6            | --ipv6        | Save subdomains with ::1 (ipv6)

### Examples

* To list all the basic options :

``python host3r.py -h``

* To enumerate subdomains of a specific domain to ban :

``python host3r.py -d example.com``

* To enumerate subdomains of a specific domain to ban and show verbosity :

``python host3r.py -d example.com -v``

* To enumerate subdomains of a specific domain to ban, show verbosity and export :

``python host3r.py -d example.com -v -o /usr/local/ban.txt``

* To enumerate subdomains of a specific domain to ban, show verbosity, export and add the ::1 (ipv6) :

``python host3r.py -d example.com -v -o /usr/local/ban.txt -6``

* To enumerate subdomains of a specific domain to ban, show verbosity and exceptions, export and add the ::1 (ipv6) :

``python host3r.py -d example.com -v -e -o /usr/local/ban.txt -6``


## License

host3r is licensed under the GNU GPL license. [LICENSE](https://github.com/rbcafe/host3r/blob/master/LICENSE) .

## Credits

* [Sublist3r](https://github.com/aboul3la/) - host3r is based on the sublist3r script.

## Version

**Current version is 0.1**

## More information

https://www.rbcafe.com/software/host3r/

https://host3r.rbcafe.com
