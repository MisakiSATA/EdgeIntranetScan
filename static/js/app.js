/**
 * 边缘安全审计工具 - 主JavaScript文件
 */

(function() {
    'use strict';

    // 全局配置
    const config = {
        apiBaseUrl: '/api',
        refreshInterval: 30000, // 30秒
        toastDuration: 3000
    };

    // API 请求封装
    const api = {
        async request(url, options = {}) {
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            const finalOptions = {...defaultOptions, ...options};

            try {
                const response = await fetch(config.apiBaseUrl + url, finalOptions);
                const data = await response.json();
                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            }
        },

        get(url) {
            return this.request(url, {method: 'GET'});
        },

        post(url, data) {
            return this.request(url, {
                method: 'POST',
                body: JSON.stringify(data)
            });
        }
    };

    // Toast 通知
    const toast = {
        show(title, message, type = 'info') {
            const toastEl = document.getElementById('resultToast');
            const titleEl = document.getElementById('toastTitle');
            const bodyEl = document.getElementById('toastBody');

            if (toastEl && titleEl && bodyEl) {
                titleEl.textContent = title;
                bodyEl.textContent = message;

                const bsToast = new bootstrap.Toast(toastEl, {
                    delay: config.toastDuration
                });
                bsToast.show();
            } else {
                alert(`${title}: ${message}`);
            }
        },

        success(message) {
            this.show('成功', message, 'success');
        },

        error(message) {
            this.show('错误', message, 'error');
        },

        info(message) {
            this.show('提示', message, 'info');
        }
    };

    // 加载指示器
    const loader = {
        show(element) {
            if (typeof element === 'string') {
                element = document.querySelector(element);
            }
            if (element) {
                element.disabled = true;
                element.dataset.originalText = element.innerHTML;
                element.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 处理中...';
            }
        },

        hide(element) {
            if (typeof element === 'string') {
                element = document.querySelector(element);
            }
            if (element && element.dataset.originalText) {
                element.disabled = false;
                element.innerHTML = element.dataset.originalText;
                delete element.dataset.originalText;
            }
        }
    };

    // 工具函数
    const utils = {
        formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
        },

        formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleString('zh-CN');
        },

        truncate(str, length) {
            if (str.length <= length) return str;
            return str.substring(0, length) + '...';
        },

        escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
    };

    // 初始化
    function init() {
        console.log('Edge Audit Tool initialized');

        // 设置全局刷新
        if (config.refreshInterval > 0) {
            setInterval(autoRefresh, config.refreshInterval);
        }
    }

    // 自动刷新
    function autoRefresh() {
        // 仅在仪表板页面自动刷新
        if (window.location.pathname === '/' || window.location.pathname === '/index') {
            // 可以在这里添加刷新逻辑
            console.log('Auto refresh triggered');
        }
    }

    // 页面加载完成后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // 导出到全局
    window.EdgeAudit = {
        api,
        toast,
        loader,
        utils
    };

})();

// 控制台美化
console.log('%c边缘安全审计工具', 'color: #0d6efd; font-size: 20px; font-weight: bold;');
console.log('%c基于香橙派 Zero 2W', 'color: #6c757d; font-size: 12px;');
