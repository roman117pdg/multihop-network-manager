import flask
import os
import logger
import io
import time
import secrets
from graphviz import Digraph
from shutil import copyfile

app = flask.Flask(__name__)
app.debug = False
app.secret_key = os.urandom(24)
users_ids = []
info = {'MAC':'', 'IP':'', 'SN':'', 'MODEL':''}
babel_man = None
BACKGROUND_COLOR = 'aliceblue'


@app.route("/", methods=['GET', 'POST'])
def start_session():
    if 'id' in flask.session:
        return flask.redirect(flask.url_for('home'))
    else:
        flask.session.pop('id', None)
        session_id = len(users_ids)
        flask.session['id'] = session_id
        users_ids.append(session_id)
        return flask.redirect(flask.url_for('home'))


@app.route("/home", methods=['GET', 'POST'])
def home():
    if 'id' in flask.session:
        if flask.request.method == 'POST':
            if flask.request.form['button_name'] == 'node_info':
                return flask.redirect(flask.url_for('node_info'))
            elif flask.request.form['button_name'] == 'net_topology':
                return flask.redirect(flask.url_for('net_topology'))
            elif flask.request.form['button_name'] == 'other':
                return flask.redirect(flask.url_for('other'))
        elif flask.request.method == 'GET':
            return flask.render_template('home.html', info=info)
    else:
        return flask.redirect(flask.url_for('start_session'))

@app.route("/node_info", methods=['GET', 'POST'])
def node_info():
    if 'id' in flask.session:
        neighbours = babel_man.get_neigh_table()
        sources = babel_man.get_source_table()
        routes = babel_man.get_route_table()
        seqno = babel_man.get_seqno()
        return flask.render_template('node_info.html', info=info, neighbours=neighbours, sources=sources, routes=routes, seqno=seqno)
    else:
        return flask.redirect(flask.url_for('start_session'))


@app.route("/net_topology", methods=['GET', 'POST'])
def net_topology():
    if 'id' in flask.session:
        nt = Digraph(comment='Network Topology', format='png')  
        nt.attr(bgcolor=BACKGROUND_COLOR)  
        nt.node('0', info['IP'], style='filled', fillcolor='red')   
        nodes = [info['IP']] 
        routes = babel_man.get_route_table()
        for route in routes:
            if route['use_flag'] == "True":
                if route['prefix'] == route['nexthop']: # to potem trzeba zmienic
                    if route['prefix'] not in nodes:
                        nt.node(str(len(nodes)), route['prefix'], style='filled', fillcolor='lightskyblue')
                        nodes.append(route['prefix'])  
                    nt.edge('0', str(nodes.index(route['prefix']))) 

        # other nodes
        other_nodes = babel_man.get_other_nodes_rts()
        for other_node in other_nodes:
            addr = other_node['addr']
            if addr not in nodes:
                nt.node(str(len(nodes)), addr, style='filled', fillcolor='lightskyblue')
                nodes.append(addr)
            prefixes = other_node['prefixes']
            nexthops = other_node['nexthops']
            for i in range(0, len(prefixes)):
                if prefixes[i] == nexthops[i]:
                    if prefixes[i] not in nodes:
                        nt.node(str(len(nodes)), prefixes[i], style='filled', fillcolor='lightskyblue')
                        nodes.append(prefixes[i])  
                    nt.edge(str(nodes.index(addr)), str(nodes.index(prefixes[i]))) 


        remove_old_images(directory="flask_app/static/images")
        time_stamp = str(time.time())
        nt.render('flask_app/static/images/net_top_'+time_stamp+'.gv')
        png_file = os.path.join('static/images/net_top_'+time_stamp+'.gv.png')
        return flask.render_template("net_topology.html", info=info, graph_png = png_file)
    else:
        return flask.redirect(flask.url_for('start_session'))

        
@app.route("/other", methods=['GET', 'POST'])
def other():
    if 'id' in flask.session:
        copyfile('logger.log', 'flask_app/logger.log')
        return flask.send_from_directory(os.path.join(''), 'logger.log', as_attachment=True)
    else:
        return flask.redirect(flask.url_for('start_session'))


def run(app_logger, bm, mac, ipv6, sn, model):
    global babel_man, info
    babel_man = bm
    info = {'MAC':mac, 'IP':ipv6, 'SN':sn, 'MODEL':model}
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0',port=port) # host='::'
    app_logger.info("flask app was started")

def set_value(value):
    global node_value
    node_value = value

def remove_old_images(directory):
    for file in os.listdir(directory):
        os.remove(directory+"/"+file)
    

# flask_thread = Thread(target = flask_qr.run, name="flask", args =(app_logger, ), daemon=True)
# app_logger.info("starting flask thread...")
# flask_thread.start()

# app_logger.info("starting flask")
# run(app_logger)