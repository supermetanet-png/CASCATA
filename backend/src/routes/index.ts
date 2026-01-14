
import { Router } from 'express';
import controlRoutes from './control.routes.js';
import dataRoutes from './data.routes.js';

const router = Router();

router.use('/control', controlRoutes);
router.use('/data/:slug', dataRoutes);

export default router;
