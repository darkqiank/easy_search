addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // 检查请求方法是否为 POST
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    // 解析请求的 JSON 主体
    const body = await request.json();
    const { q, apiEndpoints } = body;

    // 检查是否提供了必需的参数
    if (!q || !apiEndpoints || typeof apiEndpoints !== 'object') {
      return new Response('Missing or invalid parameters', { status: 400 });
    }

    // 将 apiEndpoints 转换为数组形式，方便并行请求
    const endpointEntries = Object.entries(apiEndpoints);

    // 并行请求所有 API 端点
    const responses = await Promise.all(
      endpointEntries.map(([key, endpoint]) =>
        fetchData(request, endpoint)
          .then(response => {
            if (response.ok) {
              return response.json()
                .then(data => ({ key, data, status: response.status }))
                .catch(error => ({ key, error: error.message, status: response.status }));
            } else {
              return { key, error: response.statusText, status: response.status };
            }
          })
          .catch(error => ({ key, error: error.message, status: error.status || 500 }))
      )
    );

    // 将结果拼接为 { key: apiEndpoint的返回结果, ... } 格式
    const combinedData = responses.reduce((acc, response) => {
      const { key } = response;
      if ('error' in response) {
        acc[key] = { error: response.error, status: response.status };
      } else if ('data' in response) {
        acc[key] = response.data;
      }
      return acc;
    }, {});

    // 将结果转换为 JSON 字符串
    const jsonString = JSON.stringify(combinedData);

    // 创建 Gzip 压缩流
    const gzipStream = new CompressionStream('gzip');
    const compressedStream = new Blob([jsonString]).stream().pipeThrough(gzipStream);

    // 返回压缩后的响应
    return new Response(compressedStream, {
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (error) {
    // 捕获并返回错误
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * 封装 fetch 请求
 * @param {Request} request - 原始请求对象
 * @param {string} endpoint - API 路径
 * @returns {Promise<Response>}
 */
async function fetchData(request, endpoint) {
  const baseUrl = 'https://www.virustotal.com';
  const actualUrl = new URL(endpoint, baseUrl);

  const modifiedRequest = new Request(actualUrl, {
    headers: request.headers,
    method: 'GET',
    redirect: 'follow',
  });

  const response = await fetch(modifiedRequest);
  
  // 不再抛出错误，而是返回响应对象，让调用者处理错误状态
  return response;
}