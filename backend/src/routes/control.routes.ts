
import { Router } from 'express';
import express from 'express';
import { AdminController } from '../controllers/AdminController.js';
import { backupUpload } from '../config/main.js';
import { cascataAuth } from '../middlewares/core.js';
import { controlPlaneFirewall } from '../middlewares/security.js';

const router = Router();

// Apply Body Parser specifically for Control Plane
// This fixes the login issue where req.body was undefined
router.use(express.json({ limit: '10mb' }) as any);
router.use(express.urlencoded({ extended: true, limit: '10mb' }) as any);

// Public / Auth
router.post('/auth/login', AdminController.login as any);
router.post('/auth/verify', AdminController.verify as any);
router.post('/system/ssl-check', AdminController.checkSsl as any);

// Protected Routes
router.use(controlPlaneFirewall as any);
router.use(cascataAuth as any);

router.get('/me/ip', (req: any, res: any) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    res.json({ ip: String(ip).replace('::ffff:', '') });
});

router.put('/auth/profile', AdminController.updateProfile as any);

// System Settings
router.get('/system/settings', AdminController.getSystemSettings as any);
router.post('/system/settings', AdminController.updateSystemSettings as any);

// Certificates
router.get('/system/certificates/status', AdminController.listCertificates as any);
router.post('/system/certificates', AdminController.createCertificate as any);
router.delete('/system/certificates/:domain', AdminController.deleteCertificate as any);

// Webhooks (Control)
router.post('/system/webhooks/:id/test', AdminController.testWebhook as any);

// Projects
router.get('/projects', AdminController.listProjects as any);
router.post('/projects', AdminController.createProject as any);
router.patch('/projects/:slug', AdminController.updateProject as any);
router.delete('/projects/:slug', AdminController.deleteProject as any);
router.get('/projects/:slug/export', AdminController.exportProject as any);

// Project Secrets & Security (Control Plane)
router.post('/projects/:slug/reveal-key', AdminController.revealKey as any);
router.post('/projects/:slug/rotate-keys', AdminController.rotateKeys as any);
router.post('/projects/:slug/secrets', AdminController.updateSecrets as any);
router.post('/projects/:slug/block-ip', AdminController.blockIp as any);
router.delete('/projects/:slug/blocklist/:ip', AdminController.unblockIp as any);
router.delete('/projects/:slug/logs', AdminController.purgeLogs as any);

// Webhooks List for Project (Admin View)
router.get('/projects/:slug/webhooks', AdminController.listWebhooks as any);
router.post('/projects/:slug/webhooks', AdminController.createWebhook as any);
router.patch('/projects/:slug/webhooks/:id', AdminController.updateWebhook as any);
router.delete('/projects/:slug/webhooks/:id', AdminController.deleteWebhook as any);

// Import
router.post('/projects/import/upload', backupUpload.single('file') as any, AdminController.uploadImport as any);
router.post('/projects/import/confirm', AdminController.confirmImport as any);

export default router;
