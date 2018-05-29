#!/usr/bin/env python
import argparse
import sys
import threading

import pika
import json


def connect(host, username, password, queue):

    credentials = pika.PlainCredentials(username, password)
    connection_parameters = pika.ConnectionParameters(host=host,
                                                      credentials=credentials)
    connection = pika.BlockingConnection(connection_parameters)
    channel = connection.channel()
    success = channel.queue_declare(queue=queue, durable=True)

    if not success:
        print("ERROR: Could not create/access queue.")
        connection.close()
        exit(1)

    return channel, connection


def send_message(host, username, password, queue, message):

    channel, connection = connect(host, username, password, queue)
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    success = channel.basic_publish(exchange='', routing_key=queue, body=body)
    connection.close()

    if not success:
        print("ERROR: Could not publish message.")
        exit(1)


def listen_messages(host, username, password, queue, handler):
    """
        Listen to RabbitMQ messages and execute handler on received message body
    :param host: RabbitMQ host
    :param username: RabbitMQ username
    :param password: RabbitMQ password
    :param queue: RabbitMQ queue to listen
    :param handler: function to handle message with signature handle(str: body)
    """

    # Call handler in another thread to avoid blocking pika's thread
    # This is needed to ensure the connection won't drop during long tasks
    def thread_callback(ch, method, properties, body):
        handled = handler(body.decode("utf-8"))
        if handled:
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            ch.basic_reject(delivery_tag=method.delivery_tag)

    def callback(ch, method, properties, body):
        threading.Thread(target=thread_callback, args=(ch, method, properties, body)).start()

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

    message = {"repo_address": "https://github.com/uw-swag/patch-detector.git",
               "commits": ["2daedbcb53cccfdf22d24dbff2e10312a179ea72", "878be37af5644fcfabb12babe253283f7de4cfee"],
               "vulnerability_id": "CVE-001",
               "versions": ["1.0.0", "2.0.0"]}

    send_message(host, username, password, queue, message)

    def handle_body(body):
        received_msg = json.loads(body)
        print("Received {}".format(received_msg))
        return True

    listen_messages(host, username, password, queue, handle_body)


if __name__ == '__main__':
    main()
