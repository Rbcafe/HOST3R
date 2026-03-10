## HOST3R


<p align="center">
<img src="https://www.rbcafe.com/wp-content/uploads/host3r_python_script.png" alt="host3r" width="400">
</p>

host3r is a python tool that is designed to enumerate the subdomains of a specific domain to ban. Generate a search of the subdomains and paste the results to your /etc/hosts file. Generate a search of the subdomains and save the results to a text file...


## Installation

```
git clone https://github.com/rbcafe/host3r
cd host3r
pip install -r requirements.txt
```

## Python Version

HOST3R now targets Python 3 only.

Recommended minimum version: `Python >= 3.10`

## Dependencies

`dnspython` and `requests`

```
pip install -r requirements.txt
```

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-h            | --help        | show the help message and exit
-d            | --domain      | Domain name to enumerate subdomains of
-o            | --output      | Save the results to a text file
-6            | --ipv6        | Save subdomains with ::1 (ipv6)

### Examples

* To list all the basic options :

``python host3r.py -h``

* To enumerate subdomains of a specific domain to ban :

``python host3r.py -d example.com``

* To enumerate subdomains of a specific domain and export the generated hosts entries :

``python host3r.py -d example.com -o /usr/local/ban.txt``

* To enumerate subdomains of a specific domain, export them, and include IPv6 loopback entries :

``python host3r.py -d example.com -o /usr/local/ban.txt -6``


## License

host3r is licensed under the GNU GPL license. [LICENSE](https://github.com/rbcafe/host3r/blob/master/LICENSE) .

## Credits

* [Sublist3r](https://github.com/aboul3la/) - host3r is based on the sublist3r script.

## Version

**Current version is 0.1**

## More information

https://www.rbcafe.com/software/host3r/

https://host3r.rbcafe.com
