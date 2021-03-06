This gem signs HTTP headers with the AWS4 signature for use with Amazon’s AWS APIs.

It is designed to be library agnostic.

## Usage

    # create a signer
    signer = AWS4::Signer.new(
      access_key: "key",
      secret_key: "secret",
      region: "us-east-1"
    )

    # build request
    uri = URI("https://dynamodb.us-east-1.amazonaws.com/")
    headers = {
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "Content-Type" => "application/json; charset=utf8"
    }
    body="{}"

    # sign headers
    headers = signer.sign("POST", uri, headers, body)

    # build request for AGCOD service
    . . .
    # sign headers
    headers = signer.sign("POST", uri, headers, body, false, 'AGCODService')

## License

The MIT License (MIT)

Copyright (c) 2013 Brandon Keene

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
