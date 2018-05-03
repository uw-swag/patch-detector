#!/usr/bin/env python
import argparse

import pika
import json


def connect(host, username, password, queue):
    credentials = pika.PlainCredentials(username, password)
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=host, credentials=credentials))
    channel = connection.channel()
    success = channel.queue_declare(queue=queue)

    if not success:
        print("ERROR: Could not create/access queue.")
        connection.close()
        exit(1)

    return channel, connection


def send_message(host, username, password, queue, message):

    channel, connection = connect(host, username, password, queue)
    success = channel.basic_publish(exchange='', routing_key=queue, body=json.dumps(message))
    connection.close()

    if not success:
        print("ERROR: Could not publish message.")
        exit(1)


def listen_messages(host, username, password, queue, handler):

    def callback(ch, method, properties, body):
        handled = handler(body)
        if handled:
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            ch.basic_reject(delivery_tag=method.delivery_tag)

    channel, connection = connect(host, username, password, queue)
    success = channel.basic_consume(callback, queue=queue, no_ack=False)

    if not success:
        print("ERROR: Could not subscribe to messages.")
        connection.close()
        exit(1)

    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Run RabbitMQ listener.
        '''
    )

    parser.add_argument(
        '--config',
        default='config.json',
        type=argparse.FileType('r'),
        metavar='path',
        help='JSON config file'
    )

    return parser.parse_args()


def main():

    args = process_arguments()
    config = json.load(args.config)

    # Usage example of send/listen to messages

    host = config["rabbitmq_host"]
    username = config["rabbitmq_username"]
    password = config["rabbitmq_password"]
    queue = config["rabbitmq_queue"]

    message = {"address": "http://github.com",
               "commits": ["asdfsdg", "afdgsfgrgdfs", "ghhgfdasdgfh"],
               "vulnerability_id" : "CVE-001",
               "versions": ["1.0.0", "2.0.0"]}

    send_message(host, username, password, queue, message)

    def handle_body(body):
        received_msg = json.loads(body)
        print("Received {}".format(received_msg))
        return True

    listen_messages(host, username, password, queue, handle_body)


if __name__ == '__main__':
    main()
