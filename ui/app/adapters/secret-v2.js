/* eslint-disable */
import { isEmpty } from '@ember/utils';
import ApplicationAdapter from './application';
import { encodePath } from 'vault/utils/path-encoding-helpers';

export default ApplicationAdapter.extend({
  namespace: 'v1',
  _url(backend, id) {
    let url = `${this.buildURL()}/${encodePath(backend)}/metadata/`;
    if (!isEmpty(id)) {
      // ARG TODO do a conditional here
      let [backend, path] = JSON.parse(id);
      url = url + encodePath(path);
    }
    return url;
  },

  // we override query here because the query object has a bunch of client-side
  // concerns and we only want to send "list" to the server
  query(store, type, query) {
    let { backend, id } = query;
    return this.ajax(this._url(backend, id), 'GET', { data: { list: true } }).then(resp => {
      resp.id = id;
      resp.backend = backend;
      return resp;
    });
  },

  urlForQueryRecord(query) {
    let { id, backend } = query;
    return this._url(backend, id);
  },

  queryRecord(store, type, query) {
    let { backend, id } = query;
    return this.ajax(this._url(backend, id), 'GET').then(resp => {
      resp.id = id;
      resp.backend = backend;
      return resp;
    });
  },

  detailURL(snapshot) {
    let backend = snapshot.belongsTo('engine', { id: true }) || snapshot.attr('engineId');
    let { path } = snapshot; // ARG TODO changed from id to path

    // ARG TODO not sure this is okay but current fix for issue with saving max_versions on create new version
    if (!path) {
      path = snapshot._attributes.path;
    }
    return this._url(backend, path);
  },

  urlForUpdateRecord(store, type, snapshot) {
    return this.detailURL(snapshot);
  },
  urlForCreateRecord(modelName, snapshot) {
    return this.detailURL(snapshot);
  },
  urlForDeleteRecord(store, type, snapshot) {
    return this.detailURL(snapshot);
  },
});
