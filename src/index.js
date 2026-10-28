// Punto de entrada del Worker: /api/* va al servidor; todo lo demás son los archivos de /public
import { handleApi } from './api.js';

export default {
  async fetch(request, env){
    const url = new URL(request.url);
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')){
      const parts = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
      return handleApi(request, env, parts);
    }
    return env.ASSETS.fetch(request);
  }
};
